import type { ReviewStore } from './database';
import { CATEGORIES, SEVERITIES, type Category, type Severity } from '../analysis/types';

/**
 * Read-side queries for the dashboard.
 *
 * Every statement here is a static string with named parameters - nothing is
 * interpolated, not even a WHERE fragment. The optional repository filter is
 * expressed as `(@repo IS NULL OR r.full_name = @repo)` rather than by appending
 * a clause, so there is no code path in this file that assembles SQL text at
 * runtime. A tool that flags string-built queries in other people's code has no
 * business building its own that way.
 */

export interface StatsFilter {
  /** Repository full name, or omit for all repositories. */
  repository?: string;
  /** Trailing window in days. */
  days: number;
}

export interface TrendPoint {
  date: string;
  /** Findings first observed on this day. */
  introduced: number;
  /** Findings resolved on this day. */
  resolved: number;
  /** Running total of open findings at end of day. */
  open: number;
  bySeverity: Record<Severity, number>;
}

export interface CategoryTrendPoint {
  date: string;
  counts: Record<Category, number>;
}

export interface Overview {
  totalOpen: number;
  totalResolved: number;
  openBySeverity: Record<Severity, number>;
  openByCategory: Record<Category, number>;
  introducedInWindow: number;
  resolvedInWindow: number;
  scansInWindow: number;
  repositoriesTracked: number;
  /** Mean time from first observation to resolution, in hours. */
  meanTimeToResolveHours: number | null;
  /** Median age of currently-open findings, in days. */
  medianOpenAgeDays: number | null;
}

export interface RuleCount {
  ruleId: string;
  category: Category;
  severity: Severity;
  open: number;
  total: number;
}

export interface RepositorySummary {
  fullName: string;
  open: number;
  critical: number;
  high: number;
  lastScanAt: string | null;
  scans: number;
}

export interface ScanSummaryRow {
  id: number;
  repository: string;
  pullRequestNumber: number | null;
  headSha: string;
  title: string | null;
  author: string | null;
  findingsCount: number;
  newFindingsCount: number;
  resolvedFindingsCount: number;
  filesScanned: number;
  durationMs: number;
  createdAt: string;
}

export interface OpenFindingRow {
  fingerprint: string;
  repository: string;
  ruleId: string;
  category: Category;
  severity: Severity;
  title: string;
  filePath: string;
  firstSeenAt: string;
  lastSeenAt: string;
  ageDays: number;
}

/** Bindings shared by every query: the optional repository and the window. */
function bindings(filter: StatsFilter): { repo: string | null; since: string; window: string } {
  return {
    repo: filter.repository ?? null,
    since: `-${filter.days} days`,
    // The trend window is inclusive of today, so it reaches back one day less.
    window: `-${filter.days - 1} days`,
  };
}

function emptySeverityRecord(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

function emptyCategoryRecord(): Record<Category, number> {
  return {
    'sql-injection': 0,
    authentication: 0,
    secrets: 0,
    dependencies: 0,
    authorization: 0,
    'dangerous-api': 0,
  };
}

const SQL = {
  openByGroup: `
    SELECT s.severity AS severity, s.category AS category, COUNT(*) AS count
      FROM finding_state s
      JOIN repositories r ON r.id = s.repository_id
     WHERE s.status = 'open'
       AND (@repo IS NULL OR r.full_name = @repo)
     GROUP BY s.severity, s.category`,

  resolvedTotal: `
    SELECT COUNT(*) AS count
      FROM finding_state s
      JOIN repositories r ON r.id = s.repository_id
     WHERE s.status = 'resolved'
       AND (@repo IS NULL OR r.full_name = @repo)`,

  introducedInWindow: `
    SELECT COUNT(*) AS count
      FROM finding_state s
      JOIN repositories r ON r.id = s.repository_id
     WHERE s.first_seen_at >= datetime('now', @since)
       AND (@repo IS NULL OR r.full_name = @repo)`,

  resolvedInWindow: `
    SELECT COUNT(*) AS count
      FROM finding_state s
      JOIN repositories r ON r.id = s.repository_id
     WHERE s.resolved_at IS NOT NULL
       AND s.resolved_at >= datetime('now', @since)
       AND (@repo IS NULL OR r.full_name = @repo)`,

  scansInWindow: `
    SELECT COUNT(*) AS count
      FROM scans sc
      JOIN repositories r ON r.id = sc.repository_id
     WHERE sc.created_at >= datetime('now', @since)
       AND (@repo IS NULL OR r.full_name = @repo)`,

  repositoriesTracked: `
    SELECT COUNT(DISTINCT r.id) AS count
      FROM repositories r
      JOIN finding_state s ON s.repository_id = r.id
     WHERE (@repo IS NULL OR r.full_name = @repo)`,

  meanTimeToResolve: `
    SELECT AVG((julianday(s.resolved_at) - julianday(s.first_seen_at)) * 24.0) AS hours
      FROM finding_state s
      JOIN repositories r ON r.id = s.repository_id
     WHERE s.resolved_at IS NOT NULL
       AND (@repo IS NULL OR r.full_name = @repo)`,

  openAges: `
    SELECT (julianday('now') - julianday(s.first_seen_at)) AS days
      FROM finding_state s
      JOIN repositories r ON r.id = s.repository_id
     WHERE s.status = 'open'
       AND (@repo IS NULL OR r.full_name = @repo)
     ORDER BY days`,

  introducedByDay: `
    SELECT date(s.first_seen_at) AS date, s.severity AS severity, COUNT(*) AS count
      FROM finding_state s
      JOIN repositories r ON r.id = s.repository_id
     WHERE s.first_seen_at >= date('now', @window)
       AND (@repo IS NULL OR r.full_name = @repo)
     GROUP BY date, severity`,

  resolvedByDay: `
    SELECT date(s.resolved_at) AS date, COUNT(*) AS count
      FROM finding_state s
      JOIN repositories r ON r.id = s.repository_id
     WHERE s.resolved_at IS NOT NULL
       AND s.resolved_at >= date('now', @window)
       AND (@repo IS NULL OR r.full_name = @repo)
     GROUP BY date`,

  carriedIntoWindow: `
    SELECT COUNT(*) AS count
      FROM finding_state s
      JOIN repositories r ON r.id = s.repository_id
     WHERE s.first_seen_at < date('now', @window)
       AND (s.resolved_at IS NULL OR s.resolved_at >= date('now', @window))
       AND (@repo IS NULL OR r.full_name = @repo)`,

  introducedByDayAndCategory: `
    SELECT date(s.first_seen_at) AS date, s.category AS category, COUNT(*) AS count
      FROM finding_state s
      JOIN repositories r ON r.id = s.repository_id
     WHERE s.first_seen_at >= date('now', @window)
       AND (@repo IS NULL OR r.full_name = @repo)
     GROUP BY date, category`,

  topRules: `
    SELECT s.rule_id AS ruleId,
           s.category AS category,
           s.severity AS severity,
           SUM(CASE WHEN s.status = 'open' THEN 1 ELSE 0 END) AS open,
           COUNT(*) AS total
      FROM finding_state s
      JOIN repositories r ON r.id = s.repository_id
     WHERE (@repo IS NULL OR r.full_name = @repo)
     GROUP BY s.rule_id, s.category, s.severity
     ORDER BY open DESC, total DESC
     LIMIT @limit`,

  repositorySummaries: `
    SELECT r.full_name AS fullName,
           COALESCE(SUM(CASE WHEN s.status = 'open' THEN 1 ELSE 0 END), 0) AS open,
           COALESCE(SUM(CASE WHEN s.status = 'open' AND s.severity = 'critical' THEN 1 ELSE 0 END), 0) AS critical,
           COALESCE(SUM(CASE WHEN s.status = 'open' AND s.severity = 'high' THEN 1 ELSE 0 END), 0) AS high,
           (SELECT MAX(created_at) FROM scans WHERE repository_id = r.id) AS lastScanAt,
           (SELECT COUNT(*) FROM scans WHERE repository_id = r.id) AS scans
      FROM repositories r
      LEFT JOIN finding_state s ON s.repository_id = r.id
     GROUP BY r.id
     ORDER BY critical DESC, high DESC, open DESC
     LIMIT @limit`,

  recentScans: `
    SELECT sc.id AS id,
           r.full_name AS repository,
           sc.pull_request_number AS pullRequestNumber,
           sc.head_sha AS headSha,
           sc.title AS title,
           sc.author AS author,
           sc.findings_count AS findingsCount,
           sc.new_findings_count AS newFindingsCount,
           sc.resolved_findings_count AS resolvedFindingsCount,
           sc.files_scanned AS filesScanned,
           sc.duration_ms AS durationMs,
           sc.created_at AS createdAt
      FROM scans sc
      JOIN repositories r ON r.id = sc.repository_id
     WHERE (@repo IS NULL OR r.full_name = @repo)
     ORDER BY sc.created_at DESC, sc.id DESC
     LIMIT @limit`,

  openFindings: `
    SELECT s.fingerprint AS fingerprint,
           r.full_name AS repository,
           s.rule_id AS ruleId,
           s.category AS category,
           s.severity AS severity,
           s.title AS title,
           s.file_path AS filePath,
           s.first_seen_at AS firstSeenAt,
           s.last_seen_at AS lastSeenAt,
           CAST(julianday('now') - julianday(s.first_seen_at) AS INTEGER) AS ageDays
      FROM finding_state s
      JOIN repositories r ON r.id = s.repository_id
     WHERE s.status = 'open'
       AND (@repo IS NULL OR r.full_name = @repo)
     ORDER BY CASE s.severity
                WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                WHEN 'low' THEN 3 ELSE 4 END,
              s.first_seen_at ASC
     LIMIT @limit`,

  knownRepositories: 'SELECT full_name FROM repositories ORDER BY full_name',
} as const;

export function overview(store: ReviewStore, filter: StatsFilter): Overview {
  const db = store.connection;
  const params = bindings(filter);

  const openBySeverity = emptySeverityRecord();
  const openByCategory = emptyCategoryRecord();
  let totalOpen = 0;

  const openRows = db
    .prepare<typeof params, { severity: string; category: string; count: number }>(SQL.openByGroup)
    .all(params);
  for (const row of openRows) {
    totalOpen += row.count;
    if ((SEVERITIES as readonly string[]).includes(row.severity)) {
      openBySeverity[row.severity as Severity] += row.count;
    }
    if ((CATEGORIES as readonly string[]).includes(row.category)) {
      openByCategory[row.category as Category] += row.count;
    }
  }

  const count = (sql: string): number =>
    db.prepare<typeof params, { count: number }>(sql).get(params)?.count ?? 0;

  const mttr =
    db.prepare<typeof params, { hours: number | null }>(SQL.meanTimeToResolve).get(params)?.hours ?? null;

  const ages = db
    .prepare<typeof params, { days: number }>(SQL.openAges)
    .all(params)
    .map((row) => row.days);

  return {
    totalOpen,
    totalResolved: count(SQL.resolvedTotal),
    openBySeverity,
    openByCategory,
    introducedInWindow: count(SQL.introducedInWindow),
    resolvedInWindow: count(SQL.resolvedInWindow),
    scansInWindow: count(SQL.scansInWindow),
    repositoriesTracked: count(SQL.repositoriesTracked),
    meanTimeToResolveHours: mttr === null ? null : Number(mttr.toFixed(1)),
    medianOpenAgeDays: ages.length === 0 ? null : Number(median(ages).toFixed(1)),
  };
}

function median(sorted: number[]): number {
  const mid = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 1) return sorted[mid]!;
  return ((sorted[mid - 1] ?? 0) + (sorted[mid] ?? 0)) / 2;
}

/**
 * Daily introduced/resolved counts plus a running open total.
 *
 * The running total starts from the number of findings that were already open
 * before the window began, so the line is correct even when the window does not
 * reach back to the first ever scan.
 */
export function trend(store: ReviewStore, filter: StatsFilter): TrendPoint[] {
  const db = store.connection;
  const params = bindings(filter);

  const introducedRows = db
    .prepare<typeof params, { date: string; severity: string; count: number }>(SQL.introducedByDay)
    .all(params);
  const resolvedRows = db
    .prepare<typeof params, { date: string; count: number }>(SQL.resolvedByDay)
    .all(params);
  const carried =
    db.prepare<typeof params, { count: number }>(SQL.carriedIntoWindow).get(params)?.count ?? 0;

  const introducedByDate = new Map<string, Record<Severity, number>>();
  for (const row of introducedRows) {
    const bucket = introducedByDate.get(row.date) ?? emptySeverityRecord();
    if ((SEVERITIES as readonly string[]).includes(row.severity)) {
      bucket[row.severity as Severity] += row.count;
    }
    introducedByDate.set(row.date, bucket);
  }
  const resolvedByDate = new Map(resolvedRows.map((row) => [row.date, row.count]));

  const points: TrendPoint[] = [];
  let open = carried;
  for (const date of dateRange(filter.days)) {
    const bySeverity = introducedByDate.get(date) ?? emptySeverityRecord();
    const introduced = Object.values(bySeverity).reduce((sum, value) => sum + value, 0);
    const resolved = resolvedByDate.get(date) ?? 0;
    open = Math.max(0, open + introduced - resolved);
    points.push({ date, introduced, resolved, open, bySeverity });
  }
  return points;
}

/** Introduced-per-day split by category, for a stacked view. */
export function categoryTrend(store: ReviewStore, filter: StatsFilter): CategoryTrendPoint[] {
  const params = bindings(filter);
  const rows = store.connection
    .prepare<typeof params, { date: string; category: string; count: number }>(
      SQL.introducedByDayAndCategory,
    )
    .all(params);

  const byDate = new Map<string, Record<Category, number>>();
  for (const row of rows) {
    const bucket = byDate.get(row.date) ?? emptyCategoryRecord();
    if ((CATEGORIES as readonly string[]).includes(row.category)) {
      bucket[row.category as Category] += row.count;
    }
    byDate.set(row.date, bucket);
  }

  return dateRange(filter.days).map((date) => ({
    date,
    counts: byDate.get(date) ?? emptyCategoryRecord(),
  }));
}

export function topRules(store: ReviewStore, filter: StatsFilter, limit = 10): RuleCount[] {
  const params = { ...bindings(filter), limit };
  return store.connection.prepare<typeof params, RuleCount>(SQL.topRules).all(params);
}

export function repositorySummaries(store: ReviewStore, limit = 20): RepositorySummary[] {
  const params = { limit };
  return store.connection.prepare<typeof params, RepositorySummary>(SQL.repositorySummaries).all(params);
}

export function recentScans(store: ReviewStore, filter: StatsFilter, limit = 15): ScanSummaryRow[] {
  const params = { ...bindings(filter), limit };
  return store.connection.prepare<typeof params, ScanSummaryRow>(SQL.recentScans).all(params);
}

export function openFindings(store: ReviewStore, filter: StatsFilter, limit = 50): OpenFindingRow[] {
  const params = { ...bindings(filter), limit };
  return store.connection.prepare<typeof params, OpenFindingRow>(SQL.openFindings).all(params);
}

export function knownRepositories(store: ReviewStore): string[] {
  return store.connection
    .prepare<[], { full_name: string }>(SQL.knownRepositories)
    .all()
    .map((row) => row.full_name);
}

/** ISO dates for the trailing `days`-day window, oldest first, inclusive of today. */
export function dateRange(days: number): string[] {
  const out: string[] = [];
  const today = new Date();
  for (let offset = days - 1; offset >= 0; offset -= 1) {
    const date = new Date(today.getTime() - offset * 86_400_000);
    out.push(date.toISOString().slice(0, 10));
  }
  return out;
}
