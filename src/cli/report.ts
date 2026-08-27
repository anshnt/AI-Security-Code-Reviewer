import { CATEGORY_LABELS, SEVERITIES, type Finding, type ScanSummary, type Severity } from '../analysis/types';
import { ALL_RULES } from '../analysis/engine';

/**
 * Terminal output.
 *
 * Written for someone who ran this because they were about to push, which means
 * the useful shape is: the worst thing first, enough to act on without opening
 * an editor, and a summary line that answers "am I clear?" without reading the
 * rest. The severity ordering the engine already applies does most of the work;
 * this file's job is to not get in the way of it.
 */

export interface ReportOptions {
  color: boolean;
  limit: number;
  quiet: boolean;
  failOn: Severity | 'never';
  /** Paths that could not be read, so they are not silently missing. */
  skipped: { path: string; reason: string }[];
  /** Warnings from a config file, if one was read. */
  configWarnings: string[];
  /** Describes what was scanned, for the summary line. */
  scope: string;
}

const RESET = '[0m';
const STYLE = {
  bold: '[1m',
  dim: '[2m',
  red: '[31m',
  brightRed: '[91m',
  yellow: '[33m',
  blue: '[34m',
  cyan: '[36m',
  grey: '[90m',
} as const;

const SEVERITY_STYLE: Record<Severity, keyof typeof STYLE> = {
  critical: 'brightRed',
  high: 'red',
  medium: 'yellow',
  low: 'blue',
  info: 'grey',
};

/**
 * Colour is opt-out but also auto-detected. `NO_COLOR` is honoured because it is
 * the convention, and a pipe gets plain text because escape codes in a log file
 * or a CI artefact are worse than no colour at all.
 */
export function shouldUseColor(override: boolean | null): boolean {
  if (override !== null) return override;
  if (process.env.NO_COLOR !== undefined && process.env.NO_COLOR !== '') return false;
  if (process.env.FORCE_COLOR !== undefined && process.env.FORCE_COLOR !== '0') return true;
  return Boolean(process.stdout.isTTY);
}

export function renderPretty(summary: ScanSummary, options: ReportOptions): string {
  const paint = (text: string, style: keyof typeof STYLE): string =>
    options.color ? `${STYLE[style]}${text}${RESET}` : text;

  const lines: string[] = [];

  if (options.configWarnings.length > 0) {
    lines.push(paint('Configuration problems', 'yellow'));
    for (const warning of options.configWarnings) lines.push(`  ${warning}`);
    lines.push('');
  }

  if (!options.quiet) {
    const shown = summary.findings.slice(0, options.limit);
    for (const finding of shown) {
      lines.push(...renderFinding(finding, paint));
      lines.push('');
    }
    if (summary.findings.length > shown.length) {
      const hidden = summary.findings.length - shown.length;
      lines.push(
        paint(`${hidden} further ${hidden === 1 ? 'finding' : 'findings'} not shown; raise --limit to see them.`, 'dim'),
        '',
      );
    }
  }

  lines.push(renderSummaryLine(summary, options, paint));

  if (options.skipped.length > 0) {
    const preview = options.skipped.slice(0, 5);
    lines.push(
      paint(
        `${options.skipped.length} path${options.skipped.length === 1 ? '' : 's'} could not be read: ` +
          preview.map((entry) => `${entry.path} (${entry.reason})`).join(', ') +
          (options.skipped.length > preview.length ? ', ...' : ''),
        'dim',
      ),
    );
  }

  return lines.join('\n');
}

function renderFinding(
  finding: Finding,
  paint: (text: string, style: keyof typeof STYLE) => string,
): string[] {
  const severity = paint(finding.severity.toUpperCase().padEnd(8), SEVERITY_STYLE[finding.severity]);
  const location = paint(`${finding.filePath}:${finding.line}`, 'cyan');

  return [
    `${severity} ${paint(finding.title, 'bold')}`,
    `         ${location}`,
    `         ${paint(finding.snippet, 'dim')}`,
    '',
    ...wrap(finding.description, 9),
    '',
    ...wrap(`Fix: ${finding.remediation}`, 9),
    paint(
      `         ${finding.ruleId} · ${CATEGORY_LABELS[finding.category]} · ${finding.confidence} confidence` +
        (finding.cwe?.length ? ` · ${finding.cwe.join(', ')}` : ''),
      'grey',
    ),
  ];
}

function renderSummaryLine(
  summary: ScanSummary,
  options: ReportOptions,
  paint: (text: string, style: keyof typeof STYLE) => string,
): string {
  const files = `${summary.filesScanned} ${summary.filesScanned === 1 ? 'file' : 'files'}`;
  const duration = summary.durationMs < 1000
    ? `${summary.durationMs}ms`
    : `${(summary.durationMs / 1000).toFixed(1)}s`;

  if (summary.findings.length === 0) {
    return paint(`No findings in ${files} (${options.scope}, ${duration}).`, 'bold');
  }

  const counts = SEVERITIES.filter((severity) => summary.countsBySeverity[severity] > 0)
    .map((severity) => paint(`${summary.countsBySeverity[severity]} ${severity}`, SEVERITY_STYLE[severity]))
    .join(', ');

  const blocking = countBlocking(summary.findings, options.failOn);
  const verdict =
    options.failOn === 'never'
      ? 'not gating'
      : blocking > 0
        ? paint(`${blocking} at or above ${options.failOn}`, 'brightRed')
        : `none at or above ${options.failOn}`;

  const count = `${summary.findings.length} ${summary.findings.length === 1 ? 'finding' : 'findings'}`;
  return `${paint(count, 'bold')} in ${files} (${options.scope}, ${duration}): ${counts} - ${verdict}.`;
}

const RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function countBlocking(findings: readonly Finding[], failOn: Severity | 'never'): number {
  if (failOn === 'never') return 0;
  return findings.filter((finding) => RANK[finding.severity] <= RANK[failOn]).length;
}

/** Machine-readable output, stable enough to script against. */
export function renderJson(summary: ScanSummary, options: ReportOptions): string {
  return JSON.stringify(
    {
      summary: {
        filesScanned: summary.filesScanned,
        findingsCount: summary.findings.length,
        countsBySeverity: summary.countsBySeverity,
        countsByCategory: summary.countsByCategory,
        durationMs: summary.durationMs,
        blocking: countBlocking(summary.findings, options.failOn),
        failOn: options.failOn,
        scope: options.scope,
      },
      findings: summary.findings,
      skipped: options.skipped,
      configWarnings: options.configWarnings,
    },
    null,
    2,
  );
}

/** `--list-rules`, so the ids for `--disable` are discoverable. */
export function renderRules(color: boolean): string {
  const paint = (text: string, style: keyof typeof STYLE): string =>
    color ? `${STYLE[style]}${text}${RESET}` : text;
  const lines: string[] = [paint('Analyzers', 'bold'), ''];
  for (const rule of ALL_RULES) {
    lines.push(`  ${paint(rule.id.padEnd(16), 'cyan')} ${CATEGORY_LABELS[rule.category]}`);
    lines.push(...wrap(rule.description, 4));
    lines.push('');
  }
  lines.push(
    paint('Disable a whole category with --disable <id>, or a single rule with', 'dim'),
    paint('--disable <id>/<rule>. Rule ids appear beside each finding.', 'dim'),
  );
  return lines.join('\n');
}

/** Wraps prose to a readable width with a fixed indent. */
function wrap(text: string, indent: number, width = 88): string[] {
  const pad = ' '.repeat(indent);
  const words = text.split(/\s+/).filter(Boolean);
  const lines: string[] = [];
  let current = '';
  for (const word of words) {
    if (current.length === 0) {
      current = word;
    } else if (`${current} ${word}`.length + indent <= width) {
      current += ` ${word}`;
    } else {
      lines.push(pad + current);
      current = word;
    }
  }
  if (current.length > 0) lines.push(pad + current);
  return lines;
}
