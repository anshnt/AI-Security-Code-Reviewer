import { CATEGORY_LABELS, SEVERITIES, type Finding, type Severity } from '../analysis/types';
import type { TriagedFinding, Verdict } from '../ai/triage';

/**
 * PR comment rendering.
 *
 * The comment is the entire product surface for most users, so it is written to
 * be read by someone who did not ask for it: verdict first, then only what they
 * need to act. Two rules shape the format.
 *
 * One: never bury the outcome. The first line says whether anything needs
 * attention, so a clean review costs the author two seconds.
 *
 * Two: severity earns space. Critical and high findings get the full
 * explanation and fix; medium and below are collapsed into a table. A comment
 * that treats a hardcoded AWS key and a predictable temp file with equal
 * prominence teaches people to skim past both.
 */

/** Hidden marker used to find and update this comment on the next push. */
export const COMMENT_MARKER = '<!-- security-code-reviewer:summary -->';

const SEVERITY_ICON: Record<Severity, string> = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🔵',
  info: '⚪',
};

export interface TriageSummary {
  triagedCount: number;
  refutedCount: number;
  droppedRefuted: boolean;
  model?: string;
  error?: string;
  durationMs: number;
}

const VERDICT_LABEL: Record<Verdict, string> = {
  confirmed: 'Confirmed on review',
  likely: 'Probably real',
  unclear: 'Needs a human',
  refuted: 'Judged a false positive',
};

export interface CommentOptions {
  repositoryFullName: string;
  headSha: string;
  filesScanned: number;
  durationMs: number;
  /** Fingerprints introduced by this pull request, as opposed to pre-existing. */
  newFingerprints: Set<string>;
  /** Number of previously-reported findings this push resolved. */
  resolvedCount: number;
  /** Cap on individually-rendered findings. */
  maxRendered: number;
  /** Base URL of the dashboard, for the footer link. */
  dashboardUrl?: string;
  /** Severity at which the commit status fails, for the "this blocks merge" note. */
  failOnSeverity: Severity | 'never';
  /** Present when the triage pass ran. */
  triage?: TriageSummary;
}

export function renderComment(findings: TriagedFinding[], options: CommentOptions): string {
  const parts: string[] = [COMMENT_MARKER];

  // Refuted findings are reported separately: still visible, but not counted in
  // the headline and not blocking, because presenting a judgement the tool
  // itself believes is wrong alongside real findings devalues both.
  const refuted = findings.filter((finding) => finding.triage?.verdict === 'refuted');
  const active = findings.filter((finding) => finding.triage?.verdict !== 'refuted');

  if (active.length === 0) {
    parts.push(
      '## Security review: no issues found',
      '',
      `Scanned ${options.filesScanned} changed ${plural(options.filesScanned, 'file')} in ` +
        `${formatDuration(options.durationMs)}. No SQL injection, authentication, secret, dependency, ` +
        'authorization or dangerous-API findings on the changed lines.',
    );
    if (options.resolvedCount > 0) {
      parts.push(
        '',
        `This push also resolved ${options.resolvedCount} previously reported ` +
          `${plural(options.resolvedCount, 'finding')}.`,
      );
    }
    if (refuted.length > 0) parts.push('', renderRefuted(refuted));
    parts.push('', footer(options));
    return parts.join('\n');
  }

  const counts = tally(active);
  const blocking = countBlocking(active, options.failOnSeverity);

  parts.push(
    `## Security review: ${active.length} ${plural(active.length, 'finding')}`,
    '',
    severityLine(counts),
    '',
  );

  if (blocking > 0) {
    parts.push(
      `> ${blocking} ${plural(blocking, 'finding')} at or above **${options.failOnSeverity}** ` +
        'severity, so the security status check is failing on this commit.',
      '',
    );
  }

  const ordered = [...active];
  const detailed = ordered.filter((finding) => finding.severity === 'critical' || finding.severity === 'high');
  const tabled = ordered.filter((finding) => finding.severity !== 'critical' && finding.severity !== 'high');
  const renderLimit = Math.max(1, options.maxRendered);
  const detailedShown = detailed.slice(0, renderLimit);

  for (const finding of detailedShown) {
    parts.push(renderDetailed(finding, options), '');
  }

  if (detailed.length > detailedShown.length) {
    const hidden = detailed.length - detailedShown.length;
    parts.push(
      `_${hidden} further high-severity ${plural(hidden, 'finding')} omitted to keep this comment readable._`,
      '',
    );
  }

  if (tabled.length > 0) {
    parts.push(
      `<details><summary><b>${tabled.length} lower-severity ${plural(tabled.length, 'finding')}</b></summary>`,
      '',
      '| Severity | Finding | Location | Rule |',
      '| --- | --- | --- | --- |',
    );
    for (const finding of tabled.slice(0, 50)) {
      parts.push(
        `| ${SEVERITY_ICON[finding.severity]} ${finding.severity} ` +
          `| ${escapeCell(finding.title)}${options.newFingerprints.has(finding.fingerprint) ? ' *(new)*' : ''} ` +
          `| \`${escapeCell(finding.filePath)}:${finding.line}\` ` +
          `| \`${finding.ruleId}\` |`,
      );
    }
    if (tabled.length > 50) {
      parts.push('', `_and ${tabled.length - 50} more._`);
    }
    parts.push('', '</details>', '');
  }

  if (options.resolvedCount > 0) {
    parts.push(
      `${options.resolvedCount} previously reported ${plural(options.resolvedCount, 'finding')} ` +
        'no longer appear on the changed lines.',
      '',
    );
  }

  if (refuted.length > 0) parts.push(renderRefuted(refuted), '');

  parts.push(footer(options));
  return parts.join('\n');
}

/**
 * The refuted set, collapsed. Each entry says what the analyzer thought and why
 * the review pass disagreed, so a reader can overrule it without leaving the
 * page.
 */
function renderRefuted(findings: TriagedFinding[]): string {
  const lines: string[] = [
    `<details><summary><b>${findings.length} ${plural(findings.length, 'finding')} judged a false positive on review</b></summary>`,
    '',
    'These matched a rule but the review pass concluded the surrounding code makes them harmless. ' +
      'They do not block the merge. If one looks wrong to you, it probably is - the pass is a second ' +
      'opinion, not the last word.',
    '',
  ];
  for (const finding of findings) {
    lines.push(
      `**\`${escapeCell(finding.filePath)}:${finding.line}\`** - ${escapeCell(finding.title)}`,
      '',
      `> ${finding.triage?.reasoning ?? ''}`,
      '',
      `<sub>Rule: \`${finding.ruleId}\` · analyzer said ${finding.severity} ` +
        `· review confidence ${finding.triage?.confidence ?? 'unknown'}</sub>`,
      '',
    );
  }
  lines.push('</details>');
  return lines.join('\n');
}

function renderDetailed(finding: TriagedFinding, options: CommentOptions): string {
  const isNew = options.newFingerprints.has(finding.fingerprint);
  const triage = finding.triage;

  const meta = [
    `\`${finding.filePath}:${finding.line}\``,
    CATEGORY_LABELS[finding.category],
    `**${finding.severity}** severity`,
    `${finding.confidence} confidence`,
  ];
  if (triage) {
    meta.push(
      triage.severityChangedFrom
        ? `${VERDICT_LABEL[triage.verdict]} (severity moved from ${triage.severityChangedFrom})`
        : VERDICT_LABEL[triage.verdict],
    );
  }
  if (isNew) meta.push('**introduced by this pull request**');
  if (finding.cwe?.length) meta.push(finding.cwe.join(', '));

  const lines: string[] = [
    `### ${SEVERITY_ICON[finding.severity]} ${finding.title}`,
    '',
    meta.join(' · '),
    '',
    '```',
    finding.snippet,
    '```',
    '',
    // The reviewed explanation talks about this code; the rule's talks about the
    // category. Prefer the specific one and keep the general one available.
    triage ? triage.reasoning : finding.description,
    '',
    `**How to fix.** ${triage?.fix ?? finding.remediation}`,
  ];

  if (triage) {
    lines.push(
      '',
      '<details><summary>What the rule says in general</summary>',
      '',
      finding.description,
      '',
      finding.remediation,
      '',
      '</details>',
    );
  }

  if (!triage && finding.confidence === 'low') {
    lines.push(
      '',
      '_Low confidence: this rule detects a shape that is often but not always a bug. ' +
        'If the surrounding code already handles it, add ' +
        `\`security-review-ignore ${finding.ruleId}\` on the line above with a short reason._`,
    );
  }

  lines.push(
    '',
    `<sub>Rule: \`${finding.ruleId}\` · fingerprint \`${finding.fingerprint}\`` +
      (triage ? ` · reviewed by \`${triage.model}\`` : '') +
      '</sub>',
  );
  return lines.join('\n');
}

function severityLine(counts: Record<Severity, number>): string {
  const shown = SEVERITIES.filter((severity) => counts[severity] > 0).map(
    (severity) => `${SEVERITY_ICON[severity]} **${counts[severity]}** ${severity}`,
  );
  return shown.join(' · ');
}

function footer(options: CommentOptions): string {
  const bits = [
    `<sub>Reviewed \`${options.headSha.slice(0, 7)}\` · ${options.filesScanned} ` +
      `${plural(options.filesScanned, 'file')} · ${formatDuration(options.durationMs)}`,
  ];
  if (options.triage) {
    const triage = options.triage;
    if (triage.error) {
      // Say so rather than letting the review look un-triaged for no reason.
      bits.push(` · review pass unavailable (${triage.error})`);
    } else if (triage.triagedCount > 0) {
      bits.push(
        ` · ${triage.triagedCount} ${plural(triage.triagedCount, 'finding')} reviewed` +
          (triage.refutedCount > 0
            ? `, ${triage.refutedCount} judged ${triage.droppedRefuted ? 'a false positive and dropped' : 'a false positive'}`
            : ''),
      );
    }
  }
  if (options.dashboardUrl) {
    const url = `${options.dashboardUrl}/?repo=${encodeURIComponent(options.repositoryFullName)}`;
    bits.push(` · [vulnerability trends](${url})`);
  }
  bits.push('</sub>');
  return bits.join('');
}

export function tally(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}

const RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function countBlocking(findings: TriagedFinding[], failOn: Severity | 'never'): number {
  if (failOn === 'never') return 0;
  return findings.filter(
    (finding) => finding.triage?.verdict !== 'refuted' && RANK[finding.severity] <= RANK[failOn],
  ).length;
}

/** One-line summary for the commit status, which GitHub truncates at 140 characters. */
export function renderStatusDescription(findings: TriagedFinding[], failOn: Severity | 'never'): string {
  const active = findings.filter((finding) => finding.triage?.verdict !== 'refuted');
  if (active.length === 0) return 'No security findings on the changed lines';
  const counts = tally(active);
  const shown = SEVERITIES.filter((severity) => counts[severity] > 0)
    .map((severity) => `${counts[severity]} ${severity}`)
    .join(', ');
  const blocking = countBlocking(findings, failOn);
  const verdict = blocking > 0 ? `${blocking} blocking` : 'none blocking';
  return `${shown} (${verdict})`.slice(0, 140);
}

function plural(count: number, word: string): string {
  return count === 1 ? word : `${word}s`;
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

/** Escapes pipes and newlines so a snippet cannot break out of a table cell. */
function escapeCell(value: string): string {
  return value.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}
