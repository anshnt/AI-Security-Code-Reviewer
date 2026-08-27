import { ALL_RULES } from '../analysis/engine';
import { CATEGORY_LABELS, type Finding, type Severity } from '../analysis/types';
import type { TriagedFinding } from '../ai/triage';

/**
 * SARIF 2.1.0 output.
 *
 * SARIF is how findings get into GitHub's Security tab, and once they are there
 * the platform does things this tool cannot: it tracks an alert across pushes,
 * lets a reviewer dismiss one with a reason that sticks, and shows the history
 * of a repository's alerts in one place. Emitting SARIF is therefore not a
 * checkbox - it is how findings become durable rather than living only in a
 * pull-request comment that scrolls away.
 *
 * Three details do most of the work and are easy to get wrong.
 *
 * `partialFingerprints` is what makes alert tracking work. Without it GitHub
 * matches alerts by location, so a finding closes and reopens every time
 * something above it shifts by a line, and a dismissal does not survive. The
 * content-addressed fingerprint the analyzers already produce is exactly the
 * right value.
 *
 * `security-severity` is a numeric CVSS-style score, not our severity word.
 * GitHub buckets it into critical/high/medium/low itself, so the mapping has to
 * land inside the right band or the Security tab will disagree with the pull
 * request comment about the same finding.
 *
 * `level` is a separate axis with only four values, and it drives whether an
 * alert is an error or a warning in CI. Mapping every severity to `error` makes
 * the whole set unusable as a gate.
 */

/** Worst first, matching the engine's ordering. */
const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
export const SARIF_VERSION = '2.1.0';

/** GitHub rejects a run with more results than this. */
export const MAX_RESULTS = 25_000;
/** And more than this for any single rule. */
export const MAX_RESULTS_PER_RULE = 1_000;

export interface SarifOptions {
  toolName: string;
  toolVersion: string;
  informationUri: string;
  /** Distinguishes this run from other analyses of the same commit. */
  automationId?: string;
  /** Directory the paths are relative to, when it is not the repository root. */
  workingDirectory?: string;
}

/**
 * SARIF `level` from our severity.
 *
 * Only critical and high are errors. Making everything an error means a
 * repository that turns on "fail the build on any SARIF error" fails on a
 * predictable temporary file, learns that the tool cries wolf, and turns it off.
 */
function levelFor(severity: Severity): 'error' | 'warning' | 'note' | 'none' {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
      return 'note';
    default:
      return 'none';
  }
}

/**
 * Numeric score, chosen to land in the middle of the band GitHub maps to the
 * same word we use. GitHub's thresholds are: critical >= 9.0, high >= 7.0,
 * medium >= 4.0, low >= 0.1 - so a score on a boundary is a bug report waiting
 * to happen when someone notices the two views disagree.
 *
 * `info` gets no score at all, and that is the interesting case. GitHub's
 * lowest security band starts at 0.1, so scoring an informational finding 0.1
 * would file it as a *low severity security alert* - indistinguishable in the
 * Security tab from the findings we actually call low. Omitting the property
 * leaves it as a plain alert graded by `level`, which is what informational
 * means.
 */
function securitySeverityFor(severity: Severity): string | null {
  switch (severity) {
    case 'critical':
      return '9.5';
    case 'high':
      return '8.0';
    case 'medium':
      return '5.5';
    case 'low':
      return '2.0';
    default:
      return null;
  }
}

/** SARIF's `precision`, from the analyzer's own confidence. */
function precisionFor(confidence: Finding['confidence']): string {
  switch (confidence) {
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    default:
      return 'low';
  }
}

export interface SarifLog {
  $schema: string;
  version: string;
  runs: unknown[];
}

/**
 * Builds the document.
 *
 * Rule metadata is emitted only for rules that actually fired, rather than the
 * whole catalogue. A run that declares two hundred rules and reports three
 * results makes the Security tab's rule filter useless.
 */
export function toSarif(findings: readonly TriagedFinding[], options: SarifOptions): SarifLog {
  const capped = capResults(findings);

  // Stable rule order, so two runs over the same findings produce byte-identical
  // documents - which matters for caching and for diffing uploads.
  const ruleIds = [...new Set(capped.map((finding) => finding.ruleId))].sort();
  const ruleIndex = new Map(ruleIds.map((id, index) => [id, index]));

  const rules = ruleIds.map((ruleId) => {
    const matching = capped.filter((finding) => finding.ruleId === ruleId);
    const example = matching[0]!;
    // GitHub takes an alert's severity from the *rule*, not the result, so a
    // rule firing at more than one severity - which a `severity.overrides`
    // entry or a triage adjustment can cause - has to settle on one number.
    // The worst one, because over-stating severity in the Security tab is
    // recoverable and under-stating it is the failure this tool exists to
    // prevent.
    const worstSeverity = matching.reduce<Severity>(
      (worst, finding) => (SEVERITY_ORDER[finding.severity] < SEVERITY_ORDER[worst] ? finding.severity : worst),
      example.severity,
    );
    const securityScore = securitySeverityFor(worstSeverity);
    const category = ALL_RULES.find((rule) => ruleId.startsWith(`${rule.id}/`) || ruleId === rule.id);
    const tags = [
      'security',
      `category/${example.category}`,
      ...(example.cwe ?? []).map((cwe) => `external/cwe/${cwe.toLowerCase().replace(/\s+/g, '')}`),
    ];

    return {
      id: ruleId,
      name: toPascalCase(ruleId),
      shortDescription: { text: example.title },
      fullDescription: { text: example.description },
      help: {
        text: `${example.description}\n\nHow to fix: ${example.remediation}`,
        markdown: `${example.description}\n\n**How to fix.** ${example.remediation}`,
      },
      defaultConfiguration: { level: levelFor(worstSeverity) },
      properties: {
        tags,
        precision: precisionFor(example.confidence),
        ...(securityScore === null ? {} : { 'security-severity': securityScore }),
        category: CATEGORY_LABELS[example.category],
        ...(category ? { analyzer: category.id } : {}),
      },
    };
  });

  const results = capped.map((finding) => ({
    ruleId: finding.ruleId,
    ruleIndex: ruleIndex.get(finding.ruleId)!,
    level: levelFor(finding.severity),
    message: { text: messageFor(finding) },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: finding.filePath,
            uriBaseId: '%SRCROOT%',
          },
          region: {
            startLine: Math.max(1, finding.line),
            ...(finding.endLine && finding.endLine > finding.line
              ? { endLine: finding.endLine }
              : {}),
            snippet: { text: finding.snippet },
          },
        },
      },
    ],
    // The single most important field for alert tracking across pushes.
    partialFingerprints: {
      securityReviewFingerprint: finding.fingerprint,
    },
    properties: {
      // Recorded per result as well, so a consumer that does look at results
      // sees the actual severity rather than the rule's worst case.
      severity: finding.severity,
      confidence: finding.confidence,
      category: finding.category,
      ...(finding.triage
        ? {
            reviewVerdict: finding.triage.verdict,
            reviewConfidence: finding.triage.confidence,
            reviewModel: finding.triage.model,
          }
        : {}),
    },
  }));

  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: options.toolName,
            version: options.toolVersion,
            informationUri: options.informationUri,
            rules,
          },
        },
        ...(options.automationId
          ? { automationDetails: { id: options.automationId } }
          : {}),
        ...(options.workingDirectory
          ? {
              originalUriBaseIds: {
                '%SRCROOT%': { uri: ensureTrailingSlash(options.workingDirectory) },
              },
            }
          : {}),
        results,
        // A run that hit a cap must say so, or a truncated upload looks like a
        // clean one.
        ...(capped.length < findings.length
          ? {
              invocations: [
                {
                  executionSuccessful: true,
                  toolExecutionNotifications: [
                    {
                      level: 'warning',
                      message: {
                        text:
                          `${findings.length - capped.length} findings were omitted from this run ` +
                          `because of the ${MAX_RESULTS}-result and ${MAX_RESULTS_PER_RULE}-per-rule limits.`,
                      },
                    },
                  ],
                },
              ],
            }
          : {}),
      },
    ],
  };
}

/**
 * The message shown on the alert.
 *
 * Prefers the reviewed explanation when there is one, for the same reason the
 * pull-request comment does: it talks about this code rather than the category.
 * A refuted finding says so up front, so someone reading the Security tab
 * without the pull-request context is not misled.
 */
function messageFor(finding: TriagedFinding): string {
  const triage = finding.triage;
  if (!triage) return `${finding.title}. ${finding.description}`;
  if (triage.verdict === 'refuted') {
    return (
      `${finding.title}. Judged a false positive on review: ${triage.reasoning} ` +
      `The rule's general concern: ${finding.description}`
    );
  }
  return `${finding.title}. ${triage.reasoning}`;
}

/**
 * Applies GitHub's limits, worst-first, so a truncated run keeps the findings
 * that matter. Truncating from the end of an unsorted list would drop
 * arbitrarily.
 */
export function capResults(findings: readonly TriagedFinding[]): TriagedFinding[] {
  const perRule = new Map<string, number>();
  const out: TriagedFinding[] = [];
  for (const finding of findings) {
    if (out.length >= MAX_RESULTS) break;
    const seen = perRule.get(finding.ruleId) ?? 0;
    if (seen >= MAX_RESULTS_PER_RULE) continue;
    perRule.set(finding.ruleId, seen + 1);
    out.push(finding);
  }
  return out;
}

/** `sql-injection/interpolated-query` becomes `SqlInjectionInterpolatedQuery`. */
function toPascalCase(ruleId: string): string {
  return ruleId
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join('');
}

function ensureTrailingSlash(value: string): string {
  return value.endsWith('/') ? value : `${value}/`;
}

export function renderSarif(findings: readonly TriagedFinding[], options: SarifOptions): string {
  return `${JSON.stringify(toSarif(findings, options), null, 2)}\n`;
}
