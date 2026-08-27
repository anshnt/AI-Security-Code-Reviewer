import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ReviewStore, type RecordableFinding } from '../src/storage/database';
import { triageAccuracy } from '../src/storage/queries';

function finding(overrides: Partial<RecordableFinding> = {}): RecordableFinding {
  return {
    ruleId: 'dangerous-api/ssrf',
    category: 'dangerous-api',
    severity: 'high',
    confidence: 'medium',
    title: 'Outbound request to a user-supplied URL',
    description: 'd',
    remediation: 'r',
    filePath: 'src/proxy.ts',
    line: 10,
    snippet: 's',
    fingerprint: 'fp-1',
    ...overrides,
  };
}

describe('triage verdict persistence', () => {
  let store: ReviewStore;

  beforeEach(() => {
    store = new ReviewStore(':memory:');
  });

  afterEach(() => {
    store.close();
  });

  function record(findings: RecordableFinding[]) {
    return store.recordScan({
      repositoryFullName: 'acme/app',
      pullRequestNumber: 1,
      headSha: `sha-${Math.random()}`,
      baseSha: 'base',
      title: null,
      author: null,
      filesScanned: 1,
      durationMs: 10,
      findings,
      examined: [{ path: 'src/proxy.ts', lines: null }],
    });
  }

  it('stores the verdict on both the log row and the state row', () => {
    record([
      finding({ triage: { verdict: 'refuted', confidence: 'high', model: 'test-model' } }),
    ]);
    const log = store.connection
      .prepare<[], { verdict: string; triage_confidence: string; triage_model: string }>(
        'SELECT verdict, triage_confidence, triage_model FROM findings',
      )
      .get()!;
    expect(log).toMatchObject({
      verdict: 'refuted',
      triage_confidence: 'high',
      triage_model: 'test-model',
    });
    const state = store.connection
      .prepare<[], { verdict: string }>('SELECT verdict FROM finding_state')
      .get()!;
    expect(state.verdict).toBe('refuted');
  });

  it('leaves the verdict null for an untriaged finding', () => {
    record([finding()]);
    const state = store.connection
      .prepare<[], { verdict: string | null }>('SELECT verdict FROM finding_state')
      .get()!;
    expect(state.verdict).toBeNull();
  });

  it('keeps the last verdict when a re-scan did not send the finding for triage', () => {
    record([finding({ triage: { verdict: 'confirmed', confidence: 'high', model: 'm' } })]);
    // A later scan that skipped triage has learned nothing new about it.
    record([finding()]);
    const state = store.connection
      .prepare<[], { verdict: string | null }>('SELECT verdict FROM finding_state')
      .get()!;
    expect(state.verdict).toBe('confirmed');
  });

  it('overwrites the verdict when a re-scan reaches a different conclusion', () => {
    record([finding({ triage: { verdict: 'confirmed', confidence: 'high', model: 'm' } })]);
    record([finding({ triage: { verdict: 'refuted', confidence: 'high', model: 'm' } })]);
    const state = store.connection
      .prepare<[], { verdict: string | null }>('SELECT verdict FROM finding_state')
      .get()!;
    expect(state.verdict).toBe('refuted');
  });
});

describe('triageAccuracy', () => {
  let store: ReviewStore;

  beforeEach(() => {
    store = new ReviewStore(':memory:');
  });

  afterEach(() => {
    store.close();
  });

  function seed(verdicts: (string | null)[], ruleId = 'dangerous-api/ssrf') {
    store.recordScan({
      repositoryFullName: 'acme/app',
      pullRequestNumber: 1,
      headSha: `sha-${ruleId}-${verdicts.length}`,
      baseSha: 'base',
      title: null,
      author: null,
      filesScanned: 1,
      durationMs: 10,
      findings: verdicts.map((verdict, index) =>
        finding({
          ruleId,
          fingerprint: `${ruleId}-${index}`,
          line: 10 + index,
          ...(verdict ? { triage: { verdict, confidence: 'high', model: 'm' } } : {}),
        }),
      ),
      examined: [{ path: 'src/proxy.ts', lines: null }],
    });
  }

  it('reports nothing when the pass has never run', () => {
    seed([null, null]);
    const accuracy = triageAccuracy(store, { days: 30 });
    expect(accuracy.judged).toBe(0);
    expect(accuracy.refutationRate).toBeNull();
    expect(accuracy.noisiestRules).toEqual([]);
  });

  it('counts verdicts and computes the refutation rate', () => {
    seed(['confirmed', 'confirmed', 'refuted', 'likely']);
    const accuracy = triageAccuracy(store, { days: 30 });
    expect(accuracy.judged).toBe(4);
    expect(accuracy.byVerdict).toEqual({ confirmed: 2, refuted: 1, likely: 1 });
    expect(accuracy.refutationRate).toBeCloseTo(0.25);
  });

  it('ignores untriaged findings in the denominator', () => {
    seed(['refuted', null, null, null]);
    const accuracy = triageAccuracy(store, { days: 30 });
    expect(accuracy.judged).toBe(1);
    expect(accuracy.refutationRate).toBe(1);
  });

  it('ranks the noisiest rules by refutation rate', () => {
    seed(['refuted', 'refuted', 'refuted', 'confirmed'], 'dangerous-api/insecure-temp-file');
    seed(['refuted', 'confirmed', 'confirmed', 'confirmed'], 'sql-injection/interpolated-query');
    const accuracy = triageAccuracy(store, { days: 30 });
    expect(accuracy.noisiestRules[0]!.ruleId).toBe('dangerous-api/insecure-temp-file');
    expect(accuracy.noisiestRules[0]!.refutationRate).toBeCloseTo(0.75);
  });

  it('does not report a rule with too few judgements to mean anything', () => {
    // One refutation out of one is not evidence of a noisy rule.
    seed(['refuted'], 'dangerous-api/weak-cipher');
    expect(triageAccuracy(store, { days: 30 }).noisiestRules).toEqual([]);
  });

  it('omits rules that were never refuted', () => {
    seed(['confirmed', 'confirmed', 'confirmed', 'likely'], 'secrets/hardcoded-credential');
    expect(triageAccuracy(store, { days: 30 }).noisiestRules).toEqual([]);
  });

  it('filters by repository', () => {
    seed(['refuted', 'confirmed']);
    expect(triageAccuracy(store, { days: 30, repository: 'acme/app' }).judged).toBe(2);
    expect(triageAccuracy(store, { days: 30, repository: 'acme/other' }).judged).toBe(0);
  });
});

describe('in-place upgrade of an older database', () => {
  let dir: string;
  let path: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'review-migrate-'));
    path = join(dir, 'old.sqlite');
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('adds the columns a first-release database is missing, keeping its rows', () => {
    // Reproduce the original schema: no line, verdict or triage columns.
    const legacy = new Database(path);
    legacy.exec(`
      CREATE TABLE repositories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE TABLE scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        repository_id INTEGER NOT NULL,
        pull_request_number INTEGER, head_sha TEXT NOT NULL, base_sha TEXT,
        title TEXT, author TEXT, files_scanned INTEGER NOT NULL DEFAULT 0,
        findings_count INTEGER NOT NULL DEFAULT 0, new_findings_count INTEGER NOT NULL DEFAULT 0,
        resolved_findings_count INTEGER NOT NULL DEFAULT 0, duration_ms INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE TABLE findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
        repository_id INTEGER NOT NULL, fingerprint TEXT NOT NULL, rule_id TEXT NOT NULL,
        category TEXT NOT NULL, severity TEXT NOT NULL, confidence TEXT NOT NULL,
        title TEXT NOT NULL, description TEXT NOT NULL, remediation TEXT NOT NULL,
        file_path TEXT NOT NULL, line INTEGER NOT NULL, end_line INTEGER,
        snippet TEXT NOT NULL, cwe TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE TABLE finding_state (
        repository_id INTEGER NOT NULL, fingerprint TEXT NOT NULL, rule_id TEXT NOT NULL,
        category TEXT NOT NULL, severity TEXT NOT NULL, file_path TEXT NOT NULL,
        title TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
        first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
        last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
        resolved_at TEXT, PRIMARY KEY (repository_id, fingerprint)
      );
      INSERT INTO repositories (full_name) VALUES ('acme/legacy');
      INSERT INTO finding_state (repository_id, fingerprint, rule_id, category, severity, file_path, title)
        VALUES (1, 'legacy-fp', 'secrets/aws-access-key-id', 'secrets', 'critical', 'src/old.ts', 'Old finding');
    `);
    legacy.close();

    // Opening it with the current code must upgrade rather than fail.
    const store = new ReviewStore(path);
    try {
      const columns = (table: string): string[] =>
        store.connection
          .prepare<[], { name: string }>(`PRAGMA table_info(${table})`)
          .all()
          .map((row) => row.name);

      expect(columns('findings')).toContain('verdict');
      expect(columns('findings')).toContain('triage_confidence');
      expect(columns('findings')).toContain('triage_model');
      expect(columns('finding_state')).toContain('line');
      expect(columns('finding_state')).toContain('verdict');

      // The pre-existing row survived.
      const kept = store.connection
        .prepare<[], { fingerprint: string; line: number; verdict: string | null }>(
          'SELECT fingerprint, line, verdict FROM finding_state',
        )
        .get()!;
      expect(kept.fingerprint).toBe('legacy-fp');
      expect(kept.line).toBe(0);
      expect(kept.verdict).toBeNull();

      // And the store is usable afterwards.
      const result = store.recordScan({
        repositoryFullName: 'acme/legacy',
        pullRequestNumber: 2,
        headSha: 'new',
        baseSha: 'base',
        title: null,
        author: null,
        filesScanned: 1,
        durationMs: 5,
        findings: [finding({ triage: { verdict: 'confirmed', confidence: 'high', model: 'm' } })],
        examined: [{ path: 'src/proxy.ts', lines: null }],
      });
      expect(result.scanId).toBeGreaterThan(0);
    } finally {
      store.close();
    }
  });

  it('is idempotent across repeated opens', () => {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const store = new ReviewStore(path);
      store.close();
    }
    expect(existsSync(path)).toBe(true);
  });
});
