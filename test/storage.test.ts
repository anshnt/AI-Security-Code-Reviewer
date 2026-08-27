import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ReviewStore } from '../src/storage/database';
import {
  dateRange,
  knownRepositories,
  openFindings,
  overview,
  recentScans,
  repositorySummaries,
  topRules,
  trend,
} from '../src/storage/queries';
import type { Finding } from '../src/analysis/types';

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'secrets/aws-access-key-id',
    category: 'secrets',
    severity: 'critical',
    confidence: 'high',
    title: 'AWS access key committed',
    description: 'd',
    remediation: 'r',
    filePath: 'src/config.ts',
    line: 3,
    snippet: 'const key = "AKIA..."',
    cwe: ['CWE-798'],
    fingerprint: 'fp-1',
    ...overrides,
  };
}

describe('ReviewStore', () => {
  let store: ReviewStore;

  beforeEach(() => {
    store = new ReviewStore(':memory:');
  });

  afterEach(() => {
    store.close();
  });

  function record(findings: Finding[], pullNumber = 1) {
    return store.recordScan({
      repositoryFullName: 'acme/app',
      pullRequestNumber: pullNumber,
      headSha: `sha-${pullNumber}-${findings.length}`,
      baseSha: 'base',
      title: 'Add feature',
      author: 'ansh',
      filesScanned: 2,
      durationMs: 120,
      findings,
      scannedPaths: ['src/config.ts'],
    });
  }

  it('reuses the repository row across scans', () => {
    const first = store.repositoryId('acme/app');
    expect(store.repositoryId('acme/app')).toBe(first);
    expect(store.repositoryId('acme/other')).not.toBe(first);
  });

  it('treats every finding in a first scan as new', () => {
    const result = record([finding()]);
    expect(result.newFindings).toHaveLength(1);
    expect(result.resolvedFingerprints).toEqual([]);
    expect(result.scanId).toBeGreaterThan(0);
  });

  it('does not report an unchanged finding as new on a second scan', () => {
    record([finding()]);
    const second = record([finding()]);
    expect(second.newFindings).toEqual([]);
  });

  it('resolves a finding once the scanned file comes back clean', () => {
    record([finding()]);
    const second = record([]);
    expect(second.resolvedFingerprints).toEqual(['fp-1']);
    expect(store.openFingerprints('acme/app').has('fp-1')).toBe(false);
  });

  it('leaves findings in untouched files open', () => {
    record([finding()]);
    const second = store.recordScan({
      repositoryFullName: 'acme/app',
      pullRequestNumber: 2,
      headSha: 'sha-elsewhere',
      baseSha: 'base',
      title: null,
      author: null,
      filesScanned: 1,
      durationMs: 5,
      findings: [],
      scannedPaths: ['src/unrelated.ts'],
    });
    expect(second.resolvedFingerprints).toEqual([]);
    expect(store.openFingerprints('acme/app').has('fp-1')).toBe(true);
  });

  it('reopens a finding that comes back', () => {
    record([finding()]);
    record([]);
    expect(store.openFingerprints('acme/app').has('fp-1')).toBe(false);
    record([finding()]);
    expect(store.openFingerprints('acme/app').has('fp-1')).toBe(true);
  });

  it('keeps repositories isolated from each other', () => {
    record([finding()]);
    store.recordScan({
      repositoryFullName: 'acme/other',
      pullRequestNumber: 5,
      headSha: 'x',
      baseSha: 'y',
      title: null,
      author: null,
      filesScanned: 1,
      durationMs: 10,
      findings: [],
      scannedPaths: [],
    });
    expect(store.openFingerprints('acme/other').size).toBe(0);
    expect(store.openFingerprints('acme/app').size).toBe(1);
  });

  it('returns an empty set for an unknown repository', () => {
    expect(store.openFingerprints('nobody/nothing').size).toBe(0);
  });

  it('stores the scan counters it computed', () => {
    record([finding(), finding({ fingerprint: 'fp-2', severity: 'high', line: 8 })]);
    const scans = recentScans(store, { days: 30 });
    expect(scans[0]).toMatchObject({
      repository: 'acme/app',
      pullRequestNumber: 1,
      findingsCount: 2,
      newFindingsCount: 2,
      filesScanned: 2,
    });
  });
});

describe('dashboard queries', () => {
  let store: ReviewStore;

  beforeEach(() => {
    store = new ReviewStore(':memory:');
    store.recordScan({
      repositoryFullName: 'acme/app',
      pullRequestNumber: 7,
      headSha: 'sha-a',
      baseSha: 'base',
      title: 'Add billing',
      author: 'ansh',
      filesScanned: 5,
      durationMs: 300,
      scannedPaths: ['src/config.ts'],
      findings: [
        finding(),
        finding({ fingerprint: 'fp-2', severity: 'high', category: 'sql-injection', ruleId: 'sql-injection/interpolated-query', line: 11 }),
        finding({ fingerprint: 'fp-3', severity: 'medium', category: 'dangerous-api', ruleId: 'dangerous-api/eval', line: 21 }),
      ],
    });
  });

  afterEach(() => {
    store.close();
  });

  it('summarises open findings by severity and category', () => {
    const result = overview(store, { days: 30 });
    expect(result.totalOpen).toBe(3);
    expect(result.openBySeverity.critical).toBe(1);
    expect(result.openBySeverity.high).toBe(1);
    expect(result.openByCategory.secrets).toBe(1);
    expect(result.openByCategory['sql-injection']).toBe(1);
    expect(result.introducedInWindow).toBe(3);
    expect(result.scansInWindow).toBe(1);
    expect(result.repositoriesTracked).toBe(1);
  });

  it('reports mean time to resolve once something is resolved', () => {
    expect(overview(store, { days: 30 }).meanTimeToResolveHours).toBeNull();
    store.recordScan({
      repositoryFullName: 'acme/app',
      pullRequestNumber: 7,
      headSha: 'sha-b',
      baseSha: 'base',
      title: null,
      author: null,
      filesScanned: 5,
      durationMs: 100,
      findings: [finding({ fingerprint: 'fp-9', line: 44 })],
      scannedPaths: ['src/config.ts'],
    });
    const result = overview(store, { days: 30 });
    expect(result.resolvedInWindow).toBe(3);
    expect(result.meanTimeToResolveHours).not.toBeNull();
  });

  it('filters by repository', () => {
    expect(overview(store, { days: 30, repository: 'acme/app' }).totalOpen).toBe(3);
    expect(overview(store, { days: 30, repository: 'acme/nothing' }).totalOpen).toBe(0);
  });

  it('produces one trend point per day in the window', () => {
    const points = trend(store, { days: 14 });
    expect(points).toHaveLength(14);
    expect(points[13]!.date).toBe(new Date().toISOString().slice(0, 10));
    expect(points[13]!.introduced).toBe(3);
    expect(points[13]!.open).toBe(3);
    expect(points[0]!.open).toBe(0);
  });

  it('carries pre-window findings into the opening balance', () => {
    // A one-day window starts today, so today's three introductions are inside it.
    const points = trend(store, { days: 1 });
    expect(points).toHaveLength(1);
    expect(points[0]!.open).toBe(3);
  });

  it('ranks rules by open count', () => {
    const rules = topRules(store, { days: 30 });
    expect(rules.length).toBe(3);
    expect(rules.every((rule) => rule.open === 1)).toBe(true);
  });

  it('summarises repositories worst-first', () => {
    const summaries = repositorySummaries(store);
    expect(summaries[0]).toMatchObject({ fullName: 'acme/app', open: 3, critical: 1, high: 1, scans: 1 });
    expect(summaries[0]!.lastScanAt).toBeTruthy();
  });

  it('lists open findings severity-first', () => {
    const rows = openFindings(store, { days: 30 });
    expect(rows.map((row) => row.severity)).toEqual(['critical', 'high', 'medium']);
    expect(rows[0]!.repository).toBe('acme/app');
    expect(rows[0]!.ageDays).toBe(0);
  });

  it('respects the findings limit', () => {
    expect(openFindings(store, { days: 30 }, 2)).toHaveLength(2);
  });

  it('lists known repositories', () => {
    expect(knownRepositories(store)).toEqual(['acme/app']);
  });
});

describe('dateRange', () => {
  it('returns the window oldest first, ending today', () => {
    const range = dateRange(3);
    expect(range).toHaveLength(3);
    expect(range[2]).toBe(new Date().toISOString().slice(0, 10));
    expect(range[0]! < range[2]!).toBe(true);
  });
});
