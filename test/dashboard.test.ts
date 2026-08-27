import { describe, expect, it } from 'vitest';
import { renderDashboard, type DashboardData } from '../src/dashboard/page';
import { DARK, LIGHT } from '../src/dashboard/theme';

function data(overrides: Partial<DashboardData> = {}): DashboardData {
  return {
    filter: { repository: null, days: 30 },
    repositories: ['acme/app'],
    overview: {
      totalOpen: 5,
      totalResolved: 2,
      openBySeverity: { critical: 1, high: 2, medium: 1, low: 1, info: 0 },
      openByCategory: {
        'sql-injection': 2,
        authentication: 1,
        secrets: 1,
        dependencies: 1,
        authorization: 0,
        'dangerous-api': 0,
      },
      introducedInWindow: 5,
      resolvedInWindow: 2,
      scansInWindow: 3,
      repositoriesTracked: 1,
      meanTimeToResolveHours: 36.5,
      medianOpenAgeDays: 4.2,
    },
    trend: [
      { date: '2026-08-25', introduced: 2, resolved: 0, open: 2, bySeverity: { critical: 1, high: 1, medium: 0, low: 0, info: 0 } },
      { date: '2026-08-26', introduced: 3, resolved: 0, open: 5, bySeverity: { critical: 0, high: 1, medium: 1, low: 1, info: 0 } },
    ],
    topRules: [
      { ruleId: 'sql-injection/interpolated-query', category: 'sql-injection', severity: 'critical', open: 2, total: 3 },
    ],
    repositorySummaries: [
      { fullName: 'acme/app', open: 5, critical: 1, high: 2, lastScanAt: '2026-08-26 10:00:00', scans: 3 },
    ],
    recentScans: [
      {
        id: 1,
        repository: 'acme/app',
        pullRequestNumber: 7,
        headSha: 'abcdef1234',
        title: 'Add billing',
        author: 'ansh',
        findingsCount: 5,
        newFindingsCount: 5,
        resolvedFindingsCount: 0,
        filesScanned: 4,
        durationMs: 300,
        createdAt: '2026-08-26 10:00:00',
      },
    ],
    openFindings: [
      {
        fingerprint: 'fp-1',
        repository: 'acme/app',
        ruleId: 'secrets/aws-access-key-id',
        category: 'secrets',
        severity: 'critical',
        title: 'AWS access key committed',
        filePath: 'src/config.ts',
        firstSeenAt: '2026-08-25 09:00:00',
        lastSeenAt: '2026-08-26 10:00:00',
        ageDays: 1,
      },
    ],
    ...overrides,
  };
}

describe('renderDashboard', () => {
  it('produces a complete standalone document', () => {
    const html = renderDashboard(data());
    expect(html.startsWith('<!doctype html>')).toBe(true);
    expect(html).toContain('</html>');
    expect(html).toContain('<title>Security review dashboard</title>');
  });

  it('makes no external requests', () => {
    const html = renderDashboard(data());
    expect(html).not.toMatch(/<script[^>]+src=/);
    expect(html).not.toMatch(/<link[^>]+href=["']https?:/);
    expect(html).not.toContain('cdn.');
    expect(html).not.toContain('fonts.googleapis');
  });

  it('renders the headline figures', () => {
    const html = renderDashboard(data());
    expect(html).toContain('Open findings');
    expect(html).toContain('Mean time to resolve');
    // 36.5 hours reads better as days.
    expect(html).toContain('1.5d');
    expect(html).toContain('4.2d');
  });

  it('keeps a sub-day resolve time in hours', () => {
    const html = renderDashboard(
      data({ overview: { ...data().overview, meanTimeToResolveHours: 6.4 } }),
    );
    expect(html).toContain('6.4h');
  });

  it('shows placeholders rather than zeros when there is no data', () => {
    const html = renderDashboard(
      data({
        overview: { ...data().overview, meanTimeToResolveHours: null, medianOpenAgeDays: null },
      }),
    );
    expect(html).toContain('--');
  });

  it('includes a data table so every chart has a text equivalent', () => {
    const html = renderDashboard(data());
    expect(html).toContain('id="trend-table"');
    expect(html).toContain('Daily open, introduced and resolved counts');
    expect(html).toContain('2026-08-26');
  });

  it('labels both series in the flow chart legend', () => {
    const html = renderDashboard(data());
    expect(html).toContain('>Introduced<');
    expect(html).toContain('>Resolved<');
  });

  it('defines the palette for light and for both dark scopes', () => {
    const html = renderDashboard(data());
    expect(html).toContain(LIGHT.series1);
    expect(html).toContain(DARK.series1);
    expect(html).toContain('@media (prefers-color-scheme: dark)');
    expect(html).toContain(':root[data-theme="dark"]');
  });

  it('marks the selected filter values', () => {
    const html = renderDashboard(
      data({ filter: { repository: 'acme/app', days: 90 }, repositories: ['acme/app', 'acme/api'] }),
    );
    expect(html).toContain('<option value="acme/app" selected>');
    expect(html).toContain('<option value="90" selected>');
  });

  it('escapes repository names in markup', () => {
    const html = renderDashboard(data({ repositories: ['acme/<script>alert(1)</script>'] }));
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;');
  });

  it('escapes a finding title so it cannot inject markup', () => {
    const html = renderDashboard(
      data({
        openFindings: [{ ...data().openFindings[0]!, title: '<img src=x onerror=alert(1)>' }],
      }),
    );
    expect(html).not.toContain('<img src=x onerror=alert(1)>');
    expect(html).toContain('&lt;img');
  });

  it('neutralises a closing script tag inside the inlined JSON', () => {
    const html = renderDashboard(data({ repositories: ['a</script><script>alert(1)</script>'] }));
    const jsonBlock = html.slice(html.indexOf('id="dashboard-data"'));
    expect(jsonBlock.slice(0, jsonBlock.indexOf('</script>'))).not.toContain('<script>');
  });

  it('explains the empty state when nothing has been reviewed', () => {
    const html = renderDashboard(
      data({ recentScans: [], openFindings: [], topRules: [], repositorySummaries: [], repositories: [] }),
    );
    expect(html).toContain('No reviews yet');
    expect(html).toContain('/webhook');
  });

  it('describes the severity ramp without assuming a light background', () => {
    const html = renderDashboard(data());
    // The dark ramp runs the other way, so "darker means worse" would be wrong there.
    expect(html).not.toContain('Darker means more severe');
    expect(html).toContain('Shade tracks severity');
  });

  it('links each repository row to its filtered view', () => {
    const html = renderDashboard(data());
    expect(html).toContain('/?repo=acme%2Fapp&days=30');
  });
});
