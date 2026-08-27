import { CATEGORY_LABELS, SEVERITY_RANK, type Severity } from '../analysis/types';
import type { TriagedFinding } from '../ai/triage';
import type { ReviewComment } from './client';

/**
 * Inline review comments.
 *
 * A summary comment tells the author that something is wrong somewhere; an
 * inline comment tells them which line, in the view they are already reading.
 * That difference is most of the value, so findings that can be anchored are
 * anchored and only the rest fall back to the summary.
 *
 * Three problems have to be solved to make this pleasant rather than annoying.
 *
 * GitHub keeps review comments forever - it marks them outdated when the line
 * moves but never removes them - so posting the same finding on every push
 * would bury the pull request. Each comment carries a hidden fingerprint marker
 * and anything already posted is skipped.
 *
 * Not every line is commentable. GitHub only accepts a comment on a line it is
 * showing in the diff, so a finding on a line outside the patch has to be
 * recognised in advance rather than discovered through a rejected review.
 *
 * Volume has to be bounded. Fifteen inline comments is a review; sixty is a
 * denial of service against the author's attention, so the worst findings get
 * the inline treatment and the rest stay in the summary.
 */

/** Hidden per-finding marker, used to avoid re-posting on the next push. */
export function fingerprintMarker(fingerprint: string): string {
  return `<!-- security-review:finding:${fingerprint} -->`;
}

const SEVERITY_ICON: Record<Severity, string> = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🔵',
  info: '⚪',
};

export interface InlinePlan {
  /** Comments to post, worst first. */
  comments: ReviewComment[];
  /** Findings that could not be anchored, or did not fit the budget. */
  deferred: TriagedFinding[];
  /** Findings skipped because an identical comment already exists. */
  alreadyPosted: number;
}

export interface InlineOptions {
  /** Post-change line numbers GitHub will accept a comment on, keyed by path. */
  commentableLines: Map<string, Set<number>>;
  /** Bodies of review comments already on the pull request. */
  existingBodies: string[];
  /** Cap on comments in one review. */
  maxComments: number;
  /** Only findings at or above this severity are posted inline. */
  minSeverity: Severity;
  /** Base URL of the dashboard, for the per-finding link. */
  dashboardUrl?: string;
  repositoryFullName: string;
}

export function planInlineComments(
  findings: TriagedFinding[],
  options: InlineOptions,
): InlinePlan {
  const minRank = SEVERITY_RANK[options.minSeverity];
  const alreadyPresent = new Set<string>();
  for (const body of options.existingBodies) {
    const match = /<!-- security-review:finding:([0-9a-f]+) -->/.exec(body);
    if (match?.[1]) alreadyPresent.add(match[1]);
  }

  const comments: ReviewComment[] = [];
  const deferred: TriagedFinding[] = [];
  let alreadyPosted = 0;

  for (const finding of findings) {
    if (alreadyPresent.has(finding.fingerprint)) {
      alreadyPosted += 1;
      continue;
    }
    // A refuted finding does not earn a line comment. It is in the summary, in
    // its own section, which is the right prominence for something the tool
    // itself believes is not a problem.
    if (finding.triage?.verdict === 'refuted') {
      deferred.push(finding);
      continue;
    }
    if (SEVERITY_RANK[finding.severity] > minRank) {
      deferred.push(finding);
      continue;
    }
    const commentable = options.commentableLines.get(finding.filePath);
    if (!commentable?.has(finding.line)) {
      deferred.push(finding);
      continue;
    }
    if (comments.length >= options.maxComments) {
      deferred.push(finding);
      continue;
    }
    comments.push({
      path: finding.filePath,
      line: finding.line,
      body: renderInlineBody(finding, options),
    });
  }

  return { comments, deferred, alreadyPosted };
}

/**
 * The body of one inline comment.
 *
 * Deliberately short. The reader is looking at the line already, so repeating
 * the snippet wastes the space; what they need is the consequence, the fix, and
 * a way to disagree with the tool.
 */
export function renderInlineBody(finding: TriagedFinding, options: InlineOptions): string {
  const triage = finding.triage;
  const lines: string[] = [
    fingerprintMarker(finding.fingerprint),
    `${SEVERITY_ICON[finding.severity]} **${finding.title}**`,
    '',
    triage ? triage.reasoning : finding.description,
    '',
    `**Fix.** ${triage?.fix ?? finding.remediation}`,
  ];

  const meta = [
    `${finding.severity} severity`,
    CATEGORY_LABELS[finding.category],
    `\`${finding.ruleId}\``,
  ];
  if (finding.cwe?.length) meta.push(finding.cwe.join(', '));
  if (triage?.severityChangedFrom) {
    meta.push(`severity moved from ${triage.severityChangedFrom} on review`);
  }

  lines.push('', `<sub>${meta.join(' · ')}</sub>`);
  lines.push(
    '',
    '<sub>Disagree? Add ' +
      `\`security-review-ignore ${finding.ruleId}\` on this line with a reason.</sub>`,
  );

  if (options.dashboardUrl) {
    const url = `${options.dashboardUrl}/?repo=${encodeURIComponent(options.repositoryFullName)}`;
    lines.push('', `<sub>[Vulnerability trends](${url})</sub>`);
  }

  return lines.join('\n');
}
