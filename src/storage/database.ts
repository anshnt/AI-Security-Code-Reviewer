import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import Database from 'better-sqlite3';
import type { Category, Finding, Severity } from '../analysis/types';
import { logger } from '../util/logger';

/**
 * Review history.
 *
 * The dashboard's job is to answer "is our security posture improving?", which
 * needs more than a list of current findings - it needs to know when each issue
 * appeared and when it stopped appearing. So findings are stored twice:
 *
 *   `findings`      - one row per finding per scan, the raw observation log.
 *   `finding_state` - one row per distinct issue (repo + fingerprint), tracking
 *                     first seen, last seen and resolution.
 *
 * The second table is what makes trends, mean-time-to-resolve and open/closed
 * counts cheap, and it is maintained by comparing each scan against the
 * previous state for the same repository.
 */

export interface ScanRecord {
  id: number;
  repositoryId: number;
  repositoryFullName: string;
  pullRequestNumber: number | null;
  headSha: string;
  baseSha: string | null;
  title: string | null;
  author: string | null;
  filesScanned: number;
  findingsCount: number;
  newFindingsCount: number;
  resolvedFindingsCount: number;
  durationMs: number;
  createdAt: string;
}

export interface PersistedFinding extends Finding {
  id: number;
  scanId: number;
  repositoryFullName: string;
  status: 'open' | 'resolved';
  firstSeenAt: string;
  lastSeenAt: string;
  resolvedAt: string | null;
}

export interface RecordScanInput {
  repositoryFullName: string;
  pullRequestNumber: number | null;
  headSha: string;
  baseSha: string | null;
  title: string | null;
  author: string | null;
  filesScanned: number;
  durationMs: number;
  findings: Finding[];
  /**
   * What this scan actually examined, including files that came back clean.
   *
   * Resolution is decided from this rather than from the paths that happened to
   * produce findings: a pull request that *fixes* the only issue in a file
   * would otherwise resolve nothing, because the file no longer appears in the
   * finding list.
   *
   * The line granularity matters just as much. A pull-request scan reports only
   * on the lines the author changed, so a pre-existing finding elsewhere in a
   * touched file is not re-detected - not because it was fixed, but because
   * nobody looked at it. Treating "file was scanned" as "file was fully
   * examined" silently closes findings that are still in the code.
   */
  examined: ExaminedFile[];
}

export interface ExaminedFile {
  path: string;
  /**
   * Lines examined in the post-change file, or `null` when the whole file was
   * in scope (a newly added file, or a local full-tree scan).
   */
  lines: number[] | null;
}

export interface RecordScanResult {
  scanId: number;
  /** Findings not previously seen on this repository. */
  newFindings: Finding[];
  /** Fingerprints that were open and are absent from this scan. */
  resolvedFingerprints: string[];
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS repositories (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  full_name     TEXT NOT NULL UNIQUE,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scans (
  id                      INTEGER PRIMARY KEY AUTOINCREMENT,
  repository_id           INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  pull_request_number     INTEGER,
  head_sha                TEXT NOT NULL,
  base_sha                TEXT,
  title                   TEXT,
  author                  TEXT,
  files_scanned           INTEGER NOT NULL DEFAULT 0,
  findings_count          INTEGER NOT NULL DEFAULT 0,
  new_findings_count      INTEGER NOT NULL DEFAULT 0,
  resolved_findings_count INTEGER NOT NULL DEFAULT 0,
  duration_ms             INTEGER NOT NULL DEFAULT 0,
  created_at              TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_scans_repo_created ON scans(repository_id, created_at);
CREATE INDEX IF NOT EXISTS idx_scans_pr ON scans(repository_id, pull_request_number);

CREATE TABLE IF NOT EXISTS findings (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id       INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  fingerprint   TEXT NOT NULL,
  rule_id       TEXT NOT NULL,
  category      TEXT NOT NULL,
  severity      TEXT NOT NULL,
  confidence    TEXT NOT NULL,
  title         TEXT NOT NULL,
  description   TEXT NOT NULL,
  remediation   TEXT NOT NULL,
  file_path     TEXT NOT NULL,
  line          INTEGER NOT NULL,
  end_line      INTEGER,
  snippet       TEXT NOT NULL,
  cwe           TEXT,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_repo_created ON findings(repository_id, created_at);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(repository_id, fingerprint);

CREATE TABLE IF NOT EXISTS finding_state (
  repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  fingerprint   TEXT NOT NULL,
  rule_id       TEXT NOT NULL,
  category      TEXT NOT NULL,
  severity      TEXT NOT NULL,
  file_path     TEXT NOT NULL,
  line          INTEGER NOT NULL DEFAULT 0,
  title         TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'open',
  first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen_at  TEXT NOT NULL DEFAULT (datetime('now')),
  resolved_at   TEXT,
  PRIMARY KEY (repository_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_state_status ON finding_state(repository_id, status);
CREATE INDEX IF NOT EXISTS idx_state_first_seen ON finding_state(first_seen_at);
`;

/**
 * Resolution requires an exact line match, deliberately.
 *
 * A tolerance window looks appealing - an edit above a finding shifts its line
 * number without changing the code - but it trades one error for a worse one.
 * With slack, a pull request that edits line 42 would close an untouched
 * finding at line 40, hiding a live vulnerability. Without it, a finding whose
 * line drifted before anyone fixed it stays open one review longer than
 * strictly necessary.
 *
 * Those two failure modes are not equally bad, so the asymmetry decides it:
 * a stale open finding costs a moment of attention, a falsely closed one costs
 * the vulnerability. Drift also self-corrects - the line is rewritten every
 * time the finding is re-observed.
 */

interface ScanScope {
  /** Whether this scan actually looked at the given location. */
  examined(filePath: string, line: number): boolean;
}

function buildScope(input: RecordScanInput): ScanScope {
  /** `null` in the map means the whole file was in scope. */
  const byPath = new Map<string, Set<number> | null>();

  const widen = (path: string, lines: number[] | null): void => {
    if (byPath.get(path) === null) return; // already whole-file
    if (lines === null) {
      byPath.set(path, null);
      return;
    }
    const existing = byPath.get(path) ?? new Set<number>();
    for (const line of lines) existing.add(line);
    byPath.set(path, existing);
  };

  for (const entry of input.examined) widen(entry.path, entry.lines);
  // A reported finding proves its own line was examined, even if a caller
  // forgot to declare the scope.
  for (const finding of input.findings) widen(finding.filePath, [finding.line]);

  return {
    examined(filePath: string, line: number): boolean {
      if (!byPath.has(filePath)) return false;
      const lines = byPath.get(filePath);
      if (lines === null) return true;
      if (!lines) return false;
      return lines.has(line);
    },
  };
}

export class ReviewStore {
  private readonly db: Database.Database;

  constructor(databasePath: string) {
    if (databasePath !== ':memory:') {
      mkdirSync(dirname(databasePath), { recursive: true });
    }
    this.db = new Database(databasePath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.db.exec(SCHEMA);
    logger.debug('review store ready', { databasePath });
  }

  close(): void {
    this.db.close();
  }

  /** Raw handle, for the read-side queries in `queries.ts`. */
  get connection(): Database.Database {
    return this.db;
  }

  repositoryId(fullName: string): number {
    const existing = this.db
      .prepare<[string], { id: number }>('SELECT id FROM repositories WHERE full_name = ?')
      .get(fullName);
    if (existing) return existing.id;
    const inserted = this.db
      .prepare('INSERT INTO repositories (full_name) VALUES (?)')
      .run(fullName);
    return Number(inserted.lastInsertRowid);
  }

  /**
   * Persists a scan and reconciles finding lifecycle state in one transaction.
   *
   * Reconciliation only considers findings for the *files this scan looked at*.
   * A pull-request scan sees a slice of the repository, so an issue in an
   * untouched file must not be marked resolved simply because it was not
   * observed this time.
   */
  recordScan(input: RecordScanInput): RecordScanResult {
    const run = this.db.transaction((): RecordScanResult => {
      const repositoryId = this.repositoryId(input.repositoryFullName);
      const scope = buildScope(input);

      const previouslyOpen = this.db
        .prepare<[number], { fingerprint: string; file_path: string; line: number }>(
          `SELECT fingerprint, file_path, line
             FROM finding_state
            WHERE repository_id = ? AND status = 'open'`,
        )
        .all(repositoryId);

      const currentFingerprints = new Set(input.findings.map((finding) => finding.fingerprint));
      const knownFingerprints = new Set(previouslyOpen.map((row) => row.fingerprint));

      const newFindings = input.findings.filter((finding) => !knownFingerprints.has(finding.fingerprint));
      const resolvedFingerprints = previouslyOpen
        .filter(
          (row) =>
            !currentFingerprints.has(row.fingerprint) && scope.examined(row.file_path, row.line),
        )
        .map((row) => row.fingerprint);

      const scan = this.db
        .prepare(
          `INSERT INTO scans (
             repository_id, pull_request_number, head_sha, base_sha, title, author,
             files_scanned, findings_count, new_findings_count, resolved_findings_count, duration_ms
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          repositoryId,
          input.pullRequestNumber,
          input.headSha,
          input.baseSha,
          input.title,
          input.author,
          input.filesScanned,
          input.findings.length,
          newFindings.length,
          resolvedFingerprints.length,
          input.durationMs,
        );
      const scanId = Number(scan.lastInsertRowid);

      const insertFinding = this.db.prepare(
        `INSERT INTO findings (
           scan_id, repository_id, fingerprint, rule_id, category, severity, confidence,
           title, description, remediation, file_path, line, end_line, snippet, cwe
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      );
      const upsertState = this.db.prepare(
        `INSERT INTO finding_state (
           repository_id, fingerprint, rule_id, category, severity, file_path, line, title,
           status, first_seen_at, last_seen_at, resolved_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', datetime('now'), datetime('now'), NULL)
         ON CONFLICT (repository_id, fingerprint) DO UPDATE SET
           last_seen_at = datetime('now'),
           status       = 'open',
           resolved_at  = NULL,
           severity     = excluded.severity,
           file_path    = excluded.file_path,
           line         = excluded.line,
           title        = excluded.title`,
      );

      for (const finding of input.findings) {
        insertFinding.run(
          scanId,
          repositoryId,
          finding.fingerprint,
          finding.ruleId,
          finding.category,
          finding.severity,
          finding.confidence,
          finding.title,
          finding.description,
          finding.remediation,
          finding.filePath,
          finding.line,
          finding.endLine ?? null,
          finding.snippet,
          finding.cwe ? finding.cwe.join(',') : null,
        );
        upsertState.run(
          repositoryId,
          finding.fingerprint,
          finding.ruleId,
          finding.category,
          finding.severity,
          finding.filePath,
          finding.line,
          finding.title,
        );
      }

      if (resolvedFingerprints.length > 0) {
        const resolve = this.db.prepare(
          `UPDATE finding_state
              SET status = 'resolved', resolved_at = datetime('now')
            WHERE repository_id = ? AND fingerprint = ?`,
        );
        for (const fingerprint of resolvedFingerprints) resolve.run(repositoryId, fingerprint);
      }

      return { scanId, newFindings, resolvedFingerprints };
    });

    return run();
  }

  /** Fingerprints already open on this repository, for "new vs pre-existing" labelling. */
  openFingerprints(repositoryFullName: string): Set<string> {
    const row = this.db
      .prepare<[string], { id: number }>('SELECT id FROM repositories WHERE full_name = ?')
      .get(repositoryFullName);
    if (!row) return new Set();
    const rows = this.db
      .prepare<[number], { fingerprint: string }>(
        "SELECT fingerprint FROM finding_state WHERE repository_id = ? AND status = 'open'",
      )
      .all(row.id);
    return new Set(rows.map((entry) => entry.fingerprint));
  }
}

export type { Category, Severity };
