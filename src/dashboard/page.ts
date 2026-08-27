import { CATEGORY_LABELS, type Category, type Severity } from '../analysis/types';
import type {
  Overview,
  RepositorySummary,
  RuleCount,
  ScanSummaryRow,
  TrendPoint,
  TriageAccuracy,
  OpenFindingRow,
} from '../storage/queries';
import { CLIENT_SCRIPT } from './client';
import { CATEGORY_ORDER, DARK, LIGHT, SEVERITY_ORDER } from './theme';

export interface DashboardData {
  filter: { repository: string | null; days: number };
  repositories: string[];
  overview: Overview;
  trend: TrendPoint[];
  topRules: RuleCount[];
  repositorySummaries: RepositorySummary[];
  recentScans: ScanSummaryRow[];
  openFindings: OpenFindingRow[];
  /** Absent when the triage pass has never run. */
  triage?: TriageAccuracy;
}

const WINDOWS = [7, 14, 30, 90, 180];

export function renderDashboard(data: DashboardData): string {
  const { overview, filter } = data;
  const severityRows = SEVERITY_ORDER.map((severity) => ({
    label: severity,
    value: overview.openBySeverity[severity],
    color: `var(--severity-${severity})`,
  }));
  const categoryRows = CATEGORY_ORDER.map((category) => ({
    label: CATEGORY_LABELS[category],
    value: overview.openByCategory[category],
  }));

  const payload = {
    trend: data.trend.map((point) => ({
      date: point.date,
      open: point.open,
      introduced: point.introduced,
      resolved: point.resolved,
    })),
    severity: severityRows,
    categories: categoryRows,
    severityOrder: SEVERITY_ORDER,
  };

  const scopeLabel = filter.repository ?? 'all connected repositories';

  return `<!doctype html>
<html lang="en" data-theme="">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Security review dashboard</title>
<style>${STYLES}</style>
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="topbar">
  <div class="brand">
    <span class="mark" aria-hidden="true"></span>
    <div>
      <h1>Security review</h1>
      <p>Vulnerability trends across reviewed pull requests</p>
    </div>
  </div>
  <button id="theme-toggle" type="button" class="ghost" aria-label="Switch between light and dark theme">Theme</button>
</header>

<main id="main">
  <form id="filters" class="filters" method="get" action="/">
    <label>
      <span>Repository</span>
      <select name="repo">
        <option value=""${filter.repository ? '' : ' selected'}>All repositories</option>
        ${data.repositories
          .map(
            (repository) =>
              `<option value="${escapeAttribute(repository)}"${
                repository === filter.repository ? ' selected' : ''
              }>${escapeHtml(repository)}</option>`,
          )
          .join('\n        ')}
      </select>
    </label>
    <label>
      <span>Window</span>
      <select name="days">
        ${WINDOWS.map(
          (days) =>
            `<option value="${days}"${days === filter.days ? ' selected' : ''}>Last ${days} days</option>`,
        ).join('\n        ')}
      </select>
    </label>
    <noscript><button type="submit">Apply</button></noscript>
    <p class="scope">Showing <strong>${escapeHtml(scopeLabel)}</strong></p>
  </form>

  <section class="tiles" aria-label="Headline figures">
    ${tile('Open findings', String(overview.totalOpen), `${overview.introducedInWindow} introduced in window`)}
    ${tile(
      'Critical and high',
      String(overview.openBySeverity.critical + overview.openBySeverity.high),
      `${overview.openBySeverity.critical} critical · ${overview.openBySeverity.high} high`,
      overview.openBySeverity.critical > 0 ? 'alert' : '',
    )}
    ${tile('Resolved in window', String(overview.resolvedInWindow), `${overview.totalResolved} resolved all time`)}
    ${tile(
      'Mean time to resolve',
      overview.meanTimeToResolveHours === null ? '--' : formatHours(overview.meanTimeToResolveHours),
      'first seen to resolved',
    )}
    ${tile(
      'Median open age',
      overview.medianOpenAgeDays === null ? '--' : `${overview.medianOpenAgeDays}d`,
      'of currently open findings',
    )}
    ${tile('Reviews run', String(overview.scansInWindow), `${overview.repositoriesTracked} repositories tracked`)}
    ${
      data.triage && data.triage.judged > 0
        ? tile(
            'Judged false positive',
            `${Math.round((data.triage.refutationRate ?? 0) * 100)}%`,
            `of ${data.triage.judged} reviewed on the changed lines`,
          )
        : ''
    }
  </section>

  <section class="panel">
    <div class="panel-head">
      <div>
        <h2>Open findings over time</h2>
        <p>Unresolved findings at the end of each day, last ${filter.days} days.</p>
      </div>
      <button id="table-toggle" type="button" class="ghost" aria-expanded="false" aria-controls="trend-table">
        Show data table
      </button>
    </div>
    <div id="chart-open" class="chart"></div>
    <div id="trend-table" class="table-wrap" hidden>
      <table>
        <caption>Daily open, introduced and resolved counts</caption>
        <thead><tr><th scope="col">Date</th><th scope="col">Open</th><th scope="col">Introduced</th><th scope="col">Resolved</th></tr></thead>
        <tbody>
          ${data.trend
            .map(
              (point) =>
                `<tr><td>${point.date}</td><td>${point.open}</td><td>${point.introduced}</td><td>${point.resolved}</td></tr>`,
            )
            .join('\n          ')}
        </tbody>
      </table>
    </div>
  </section>

  <section class="panel">
    <div class="panel-head">
      <div>
        <h2>Introduced against resolved</h2>
        <p>Bars above the line are findings newly detected that day; bars below are findings that stopped appearing.</p>
      </div>
      <ul class="legend">
        <li><span class="swatch" style="background: var(--series-1)"></span>Introduced</li>
        <li><span class="swatch" style="background: var(--series-2)"></span>Resolved</li>
      </ul>
    </div>
    <div id="chart-flow" class="chart"></div>
  </section>

  <div class="grid-2">
    <section class="panel">
      <h2>Open by severity</h2>
      <p>Shade tracks severity along a single hue. Every bar is labelled, so colour is never the only cue.</p>
      <div id="chart-severity" class="bars"></div>
    </section>
    <section class="panel">
      <h2>Open by category</h2>
      <p>The six checks the reviewer runs on every pull request.</p>
      <div id="chart-category" class="bars"></div>
    </section>
  </div>

  <div class="grid-2">
    <section class="panel">
      <h2>Most frequent rules</h2>
      ${
        data.topRules.length === 0
          ? '<p class="empty">No findings recorded yet.</p>'
          : `<div class="table-wrap"><table>
        <thead><tr><th scope="col">Rule</th><th scope="col">Severity</th><th scope="col">Open</th><th scope="col">Total</th></tr></thead>
        <tbody>
          ${data.topRules
            .map(
              (rule) => `<tr>
            <td><code>${escapeHtml(rule.ruleId)}</code></td>
            <td>${severityChip(rule.severity)}</td>
            <td>${rule.open}</td><td>${rule.total}</td>
          </tr>`,
            )
            .join('\n          ')}
        </tbody></table></div>`
      }
    </section>

    <section class="panel">
      <h2>Repositories</h2>
      ${
        data.repositorySummaries.length === 0
          ? '<p class="empty">No repositories connected yet.</p>'
          : `<div class="table-wrap"><table>
        <thead><tr><th scope="col">Repository</th><th scope="col">Open</th><th scope="col">Critical</th><th scope="col">High</th><th scope="col">Last review</th></tr></thead>
        <tbody>
          ${data.repositorySummaries
            .map(
              (repository) => `<tr>
            <td><a href="/?repo=${encodeURIComponent(repository.fullName)}&days=${filter.days}">${escapeHtml(
              repository.fullName,
            )}</a></td>
            <td>${repository.open}</td>
            <td>${repository.critical}</td>
            <td>${repository.high}</td>
            <td>${repository.lastScanAt ? escapeHtml(repository.lastScanAt) : '--'}</td>
          </tr>`,
            )
            .join('\n          ')}
        </tbody></table></div>`
      }
    </section>
  </div>

  ${
    data.triage && data.triage.noisiestRules.length > 0
      ? `<section class="panel">
    <h2>Rules the review pass disagrees with most</h2>
    <p>A rule refuted on most of its findings is a rule to tune or switch off in
    <code>.securityreview.yml</code>. Only rules with at least three judgements appear here,
    because one refutation out of one is not evidence.</p>
    <div class="table-wrap"><table>
      <thead><tr><th scope="col">Rule</th><th scope="col">Refuted</th><th scope="col">Judged</th><th scope="col">Rate</th></tr></thead>
      <tbody>
        ${data.triage.noisiestRules
          .map(
            (rule) => `<tr>
          <td><code>${escapeHtml(rule.ruleId)}</code></td>
          <td>${rule.refuted}</td>
          <td>${rule.judged}</td>
          <td>${Math.round(rule.refutationRate * 100)}%</td>
        </tr>`,
          )
          .join('\n        ')}
      </tbody></table></div>
  </section>`
      : ''
  }

  <section class="panel">
    <h2>Oldest open findings</h2>
    <p>Sorted by severity, then by how long they have been outstanding.</p>
    ${
      data.openFindings.length === 0
        ? '<p class="empty">Nothing open. </p>'
        : `<div class="table-wrap"><table>
      <thead><tr><th scope="col">Severity</th><th scope="col">Finding</th><th scope="col">Location</th><th scope="col">Age</th></tr></thead>
      <tbody>
        ${data.openFindings
          .map(
            (finding) => `<tr>
          <td>${severityChip(finding.severity)}</td>
          <td>${escapeHtml(finding.title)}<br><small>${escapeHtml(finding.ruleId)}</small></td>
          <td><code>${escapeHtml(finding.repository)}</code><br><code>${escapeHtml(finding.filePath)}</code></td>
          <td>${finding.ageDays}d</td>
        </tr>`,
          )
          .join('\n        ')}
      </tbody></table></div>`
    }
  </section>

  <section class="panel">
    <h2>Recent reviews</h2>
    ${
      data.recentScans.length === 0
        ? '<p class="empty">No reviews yet. Point a repository webhook at <code>/webhook</code> to get started.</p>'
        : `<div class="table-wrap"><table>
      <thead><tr><th scope="col">Repository</th><th scope="col">Pull request</th><th scope="col">Findings</th><th scope="col">New</th><th scope="col">Resolved</th><th scope="col">Files</th><th scope="col">When</th></tr></thead>
      <tbody>
        ${data.recentScans
          .map(
            (scan) => `<tr>
          <td><code>${escapeHtml(scan.repository)}</code></td>
          <td>${
            scan.pullRequestNumber
              ? `<a href="https://github.com/${escapeAttribute(scan.repository)}/pull/${
                  scan.pullRequestNumber
                }" rel="noreferrer noopener">#${scan.pullRequestNumber}</a> ${escapeHtml(
                  truncateText(scan.title ?? '', 60),
                )}`
              : '--'
          }</td>
          <td>${scan.findingsCount}</td>
          <td>${scan.newFindingsCount}</td>
          <td>${scan.resolvedFindingsCount}</td>
          <td>${scan.filesScanned}</td>
          <td>${escapeHtml(scan.createdAt)}</td>
        </tr>`,
          )
          .join('\n        ')}
      </tbody></table></div>`
    }
  </section>
</main>

<div id="tooltip" class="tooltip" role="status" hidden></div>
<script type="application/json" id="dashboard-data">${escapeJsonForScript(payload)}</script>
<script>${CLIENT_SCRIPT}</script>
</body>
</html>`;
}

function tile(label: string, value: string, detail: string, variant = ''): string {
  return `<article class="tile ${variant}">
      <p class="tile-label">${escapeHtml(label)}</p>
      <p class="tile-value">${escapeHtml(value)}</p>
      <p class="tile-detail">${escapeHtml(detail)}</p>
    </article>`;
}

function severityChip(severity: Severity): string {
  return `<span class="chip"><span class="dot" style="background: var(--severity-${severity})"></span>${severity}</span>`;
}

function formatHours(hours: number): string {
  if (hours < 24) return `${hours.toFixed(1)}h`;
  return `${(hours / 24).toFixed(1)}d`;
}

function truncateText(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max - 1)}...` : value;
}

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function escapeAttribute(value: string): string {
  return escapeHtml(value);
}

/**
 * Inline JSON has one escape hazard: a `</script>` sequence inside a string
 * value terminates the block early, which turns data into markup. Escaping the
 * angle brackets closes that off.
 */
function escapeJsonForScript(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

/**
 * Palette roles are declared once on `:root` for light, then redefined for dark
 * under both the OS media query and an explicit `data-theme` stamp, so the
 * in-page toggle wins in either direction.
 */
const STYLES = `
:root {
  color-scheme: light;
  --surface: ${LIGHT.surface};
  --surface-raised: ${LIGHT.surfaceRaised};
  --border: ${LIGHT.border};
  --grid: ${LIGHT.grid};
  --text-primary: ${LIGHT.textPrimary};
  --text-secondary: ${LIGHT.textSecondary};
  --text-muted: ${LIGHT.textMuted};
  --series-1: ${LIGHT.series1};
  --series-2: ${LIGHT.series2};
  --severity-critical: ${LIGHT.severityRamp.critical};
  --severity-high: ${LIGHT.severityRamp.high};
  --severity-medium: ${LIGHT.severityRamp.medium};
  --severity-low: ${LIGHT.severityRamp.low};
  --severity-info: ${LIGHT.severityRamp.info};
  --radius: 10px;
  --font: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root:where(:not([data-theme="light"])) {
    color-scheme: dark;
    --surface: ${DARK.surface};
    --surface-raised: ${DARK.surfaceRaised};
    --border: ${DARK.border};
    --grid: ${DARK.grid};
    --text-primary: ${DARK.textPrimary};
    --text-secondary: ${DARK.textSecondary};
    --text-muted: ${DARK.textMuted};
    --series-1: ${DARK.series1};
    --series-2: ${DARK.series2};
    --severity-critical: ${DARK.severityRamp.critical};
    --severity-high: ${DARK.severityRamp.high};
    --severity-medium: ${DARK.severityRamp.medium};
    --severity-low: ${DARK.severityRamp.low};
    --severity-info: ${DARK.severityRamp.info};
  }
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --surface: ${DARK.surface};
  --surface-raised: ${DARK.surfaceRaised};
  --border: ${DARK.border};
  --grid: ${DARK.grid};
  --text-primary: ${DARK.textPrimary};
  --text-secondary: ${DARK.textSecondary};
  --text-muted: ${DARK.textMuted};
  --series-1: ${DARK.series1};
  --series-2: ${DARK.series2};
  --severity-critical: ${DARK.severityRamp.critical};
  --severity-high: ${DARK.severityRamp.high};
  --severity-medium: ${DARK.severityRamp.medium};
  --severity-low: ${DARK.severityRamp.low};
  --severity-info: ${DARK.severityRamp.info};
}

* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 0 0 64px;
  background: var(--surface);
  color: var(--text-primary);
  font-family: var(--font);
  font-size: 15px;
  line-height: 1.55;
  -webkit-font-smoothing: antialiased;
}
.skip {
  position: absolute; left: -9999px;
}
.skip:focus {
  left: 12px; top: 12px; z-index: 20; padding: 8px 12px;
  background: var(--surface-raised); border: 1px solid var(--border); border-radius: 8px;
}
.topbar {
  display: flex; align-items: center; justify-content: space-between; gap: 16px;
  padding: 22px 28px; border-bottom: 1px solid var(--border);
  max-width: 1180px; margin: 0 auto;
}
.brand { display: flex; align-items: center; gap: 14px; }
.mark {
  width: 34px; height: 34px; border-radius: 9px; flex: none;
  background: linear-gradient(140deg, var(--series-1), var(--series-2));
}
.topbar h1 { margin: 0; font-size: 17px; letter-spacing: -0.01em; }
.topbar p { margin: 0; font-size: 13px; color: var(--text-secondary); }
.ghost {
  font: inherit; font-size: 13px; padding: 7px 13px; cursor: pointer;
  color: var(--text-secondary); background: var(--surface-raised);
  border: 1px solid var(--border); border-radius: 8px;
}
.ghost:hover { color: var(--text-primary); }

main { max-width: 1180px; margin: 0 auto; padding: 24px 28px 0; }
@media (max-width: 560px) {
  .topbar { padding: 18px 16px; }
  main { padding: 18px 16px 0; }
  .panel { padding: 16px 14px; }
  .filters select { min-width: 0; width: 100%; }
  .filters label { flex: 1 1 140px; }
  .filters .scope { margin: 6px 0 0; flex: 1 1 100%; }
}

.filters {
  display: flex; align-items: flex-end; gap: 14px; flex-wrap: wrap;
  margin-bottom: 22px;
}
.filters label { display: flex; flex-direction: column; gap: 5px; font-size: 12px; color: var(--text-secondary); }
.filters select {
  font: inherit; font-size: 14px; padding: 7px 10px; min-width: 190px;
  color: var(--text-primary); background: var(--surface-raised);
  border: 1px solid var(--border); border-radius: 8px;
}
.filters .scope { margin: 0 0 6px auto; font-size: 13px; color: var(--text-secondary); }

.tiles {
  display: grid; gap: 14px; margin-bottom: 22px;
  grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
}
.tile {
  padding: 16px 18px; background: var(--surface-raised);
  border: 1px solid var(--border); border-radius: var(--radius);
}
.tile.alert { border-color: var(--severity-critical); }
.tile-label { margin: 0; font-size: 12px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.05em; }
.tile-value { margin: 6px 0 2px; font-size: 30px; font-weight: 600; letter-spacing: -0.02em; font-variant-numeric: tabular-nums; }
.tile-detail { margin: 0; font-size: 12px; color: var(--text-muted); }

.panel {
  padding: 20px 22px; margin-bottom: 22px; background: var(--surface-raised);
  border: 1px solid var(--border); border-radius: var(--radius);
  /* Grid and flex items default to min-width:auto, which lets a wide table
     inside push the whole page sideways. Overriding it is what actually keeps
     the horizontal scroll inside .table-wrap where it belongs. */
  min-width: 0;
}
.panel h2 { margin: 0; font-size: 15px; letter-spacing: -0.01em; }
.panel > p, .panel-head p { margin: 4px 0 0; font-size: 13px; color: var(--text-secondary); max-width: 70ch; }
.panel-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; flex-wrap: wrap; }
.grid-2 { display: grid; gap: 22px; grid-template-columns: minmax(0, 1fr); }
.grid-2 > * { min-width: 0; }
@media (min-width: 900px) { .grid-2 { grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); } }

.chart { margin-top: 14px; min-height: 240px; max-width: 100%; overflow: hidden; }
.axis-label { font-size: 11px; fill: var(--text-muted); font-family: var(--font); }
.end-label { font-size: 12px; font-weight: 600; fill: var(--text-secondary); font-family: var(--font); }
.bar { transition: opacity 120ms ease; }
.hit { cursor: default; }
.hit:hover ~ .bar { opacity: 1; }

.legend { display: flex; gap: 16px; margin: 0; padding: 0; list-style: none; font-size: 13px; color: var(--text-secondary); }
.legend li { display: flex; align-items: center; gap: 7px; }
.swatch { width: 11px; height: 11px; border-radius: 3px; display: inline-block; }

.bars { margin-top: 14px; }
.bar-rows { display: flex; flex-direction: column; gap: 8px; }
.bar-row { display: grid; grid-template-columns: 96px minmax(0, 1fr) 40px; align-items: center; gap: 12px; }
.bar-label { font-size: 13px; color: var(--text-secondary); text-transform: capitalize; }
.bar-track { height: 12px; background: var(--grid); border-radius: 6px; overflow: hidden; }
.bar-fill { height: 100%; border-radius: 6px; min-width: 2px; transition: width 200ms ease; }
.bar-value { font-size: 13px; text-align: right; font-variant-numeric: tabular-nums; color: var(--text-primary); }

.table-wrap { margin-top: 14px; overflow-x: auto; max-width: 100%; }
/* Wide tables scroll inside their own container rather than crushing columns. */
table { width: 100%; min-width: 420px; border-collapse: collapse; font-size: 13px; }
caption { text-align: left; font-size: 12px; color: var(--text-secondary); padding-bottom: 8px; }
th, td { text-align: left; padding: 9px 12px 9px 0; border-bottom: 1px solid var(--border); vertical-align: top; }
th { font-weight: 600; font-size: 12px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.04em; }
td { color: var(--text-primary); }
td small { color: var(--text-muted); font-size: 11px; }
code { font-family: var(--mono); font-size: 12px; color: var(--text-secondary); }
a { color: var(--series-1); }

.chip { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; text-transform: capitalize; white-space: nowrap; }
.dot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; flex: none; }
.empty { color: var(--text-muted); font-size: 13px; margin-top: 12px; }

.tooltip {
  position: fixed; z-index: 40; pointer-events: none;
  display: flex; flex-direction: column; gap: 2px;
  padding: 9px 11px; border-radius: 8px; font-size: 12px; line-height: 1.4;
  background: var(--surface-raised); color: var(--text-primary);
  border: 1px solid var(--border); box-shadow: 0 6px 20px rgb(0 0 0 / 0.14);
}
.tooltip[hidden] { display: none; }
.tooltip strong { font-size: 12px; }
.tooltip span { color: var(--text-secondary); font-variant-numeric: tabular-nums; }
`;

export type { Category, Severity };
