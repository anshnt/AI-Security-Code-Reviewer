import { describe, expect, it } from 'vitest';
import {
  COMMENT_MARKER,
  countBlocking,
  renderComment,
  renderStatusDescription,
  tally,
} from '../src/github/comment';
import type { Finding } from '../src/analysis/types';

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'sql-injection/interpolated-query',
    category: 'sql-injection',
    severity: 'critical',
    confidence: 'high',
    title: 'SQL query built by string interpolation',
    description: 'Interpolated request data into SQL.',
    remediation: 'Bind the value as a parameter.',
    filePath: 'src/users.ts',
    line: 12,
    snippet: 'db.query(`SELECT * FROM users WHERE id = ${id}`)',
    cwe: ['CWE-89'],
    fingerprint: 'fp-critical',
    ...overrides,
  };
}

const baseOptions = {
  repositoryFullName: 'acme/app',
  headSha: '0123456789abcdef',
  filesScanned: 4,
  durationMs: 850,
  newFingerprints: new Set<string>(),
  resolvedCount: 0,
  maxRendered: 10,
  failOnSeverity: 'high' as const,
};

describe('renderComment', () => {
  it('starts with the hidden marker so the comment can be updated in place', () => {
    expect(renderComment([], baseOptions).startsWith(COMMENT_MARKER)).toBe(true);
  });

  it('leads with the verdict when nothing was found', () => {
    const body = renderComment([], baseOptions);
    expect(body).toContain('no issues found');
    expect(body).toContain('4 changed files');
  });

  it('mentions resolved findings on a clean run', () => {
    const body = renderComment([], { ...baseOptions, resolvedCount: 3 });
    expect(body).toContain('resolved 3 previously reported findings');
  });

  it('renders critical findings in full', () => {
    const body = renderComment([finding()], baseOptions);
    expect(body).toContain('1 finding');
    expect(body).toContain('SQL query built by string interpolation');
    expect(body).toContain('src/users.ts:12');
    expect(body).toContain('**How to fix.**');
    expect(body).toContain('CWE-89');
  });

  it('collapses lower-severity findings into a table', () => {
    const body = renderComment(
      [finding({ severity: 'medium', fingerprint: 'fp-medium', title: 'Predictable temp file' })],
      baseOptions,
    );
    expect(body).toContain('<details>');
    expect(body).toContain('| Severity | Finding | Location | Rule |');
    expect(body).not.toContain('**How to fix.**');
  });

  it('marks findings the pull request introduced', () => {
    const body = renderComment([finding()], {
      ...baseOptions,
      newFingerprints: new Set(['fp-critical']),
    });
    expect(body).toContain('introduced by this pull request');
  });

  it('says when the status check is failing and why', () => {
    const body = renderComment([finding()], baseOptions);
    expect(body).toContain('security status check is failing');
  });

  it('does not claim a failing check when nothing blocks', () => {
    const body = renderComment([finding({ severity: 'low', fingerprint: 'fp-low' })], baseOptions);
    expect(body).not.toContain('status check is failing');
  });

  it('adds triage guidance to low-confidence findings', () => {
    const body = renderComment([finding({ confidence: 'low' })], baseOptions);
    expect(body).toContain('security-review-ignore');
  });

  it('caps the number of fully rendered findings', () => {
    const many = Array.from({ length: 8 }, (_, index) =>
      finding({ fingerprint: `fp-${index}`, line: index + 1 }),
    );
    const body = renderComment(many, { ...baseOptions, maxRendered: 3 });
    expect(body).toContain('5 further high-severity findings omitted');
  });

  it('escapes a pipe so a snippet cannot break the table', () => {
    const body = renderComment(
      [finding({ severity: 'low', fingerprint: 'fp-pipe', title: 'a | b', filePath: 'x|y.ts' })],
      baseOptions,
    );
    expect(body).toContain('a \\| b');
    expect(body).toContain('x\\|y.ts');
  });

  it('links to the dashboard when a public URL is configured', () => {
    const body = renderComment([], { ...baseOptions, dashboardUrl: 'https://review.example.com' });
    expect(body).toContain('https://review.example.com/?repo=acme%2Fapp');
  });
});

describe('status reporting', () => {
  it('summarises a clean review', () => {
    expect(renderStatusDescription([], 'high')).toBe('No security findings on the changed lines');
  });

  it('summarises counts and how many block', () => {
    const description = renderStatusDescription(
      [finding(), finding({ severity: 'low', fingerprint: 'b' })],
      'high',
    );
    expect(description).toContain('1 critical');
    expect(description).toContain('1 low');
    expect(description).toContain('1 blocking');
  });

  it('stays inside the GitHub description limit', () => {
    const many = Array.from({ length: 200 }, (_, index) => finding({ fingerprint: `fp-${index}` }));
    expect(renderStatusDescription(many, 'high').length).toBeLessThanOrEqual(140);
  });

  it('counts blocking findings at or above the threshold', () => {
    const findings = [
      finding({ severity: 'critical', fingerprint: 'a' }),
      finding({ severity: 'high', fingerprint: 'b' }),
      finding({ severity: 'medium', fingerprint: 'c' }),
    ];
    expect(countBlocking(findings, 'high')).toBe(2);
    expect(countBlocking(findings, 'critical')).toBe(1);
    expect(countBlocking(findings, 'never')).toBe(0);
  });

  it('tallies by severity', () => {
    expect(tally([finding(), finding({ severity: 'low', fingerprint: 'b' })])).toEqual({
      critical: 1,
      high: 0,
      medium: 0,
      low: 1,
      info: 0,
    });
  });
});
