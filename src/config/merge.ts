import type { AppConfig } from '../config';
import type { RepoConfig } from './repo-config';

/**
 * Combines the service-level configuration with a repository's own file.
 *
 * The repository wins on everything it sets, with one exception: it cannot
 * *loosen* the severity at which the check fails. A team may say "fail on
 * medium here, we are stricter than the default"; a team saying "never fail" is
 * asking to remove the merge gate from their own pull requests, which is a
 * decision for whoever owns the deployment, not for whoever owns the file. So
 * `fail-on` may only tighten, and an attempt to loosen it is reported.
 *
 * Everything else is a genuine local preference. A vendored directory that
 * should be skipped, a rule that misfires on this codebase, a lower inline
 * comment budget - the repository knows better than the service does.
 */

/**
 * Strictness, where a higher number gates more.
 *
 * Note this is the inverse of the severity ranking used elsewhere: failing at
 * `medium` catches medium, high and critical, so it is *stricter* than failing
 * at `critical`, even though critical is the more severe word. `never` removes
 * the gate entirely and is therefore the loosest value there is, not the
 * strictest - getting that backwards would let a repository turn its own merge
 * gate off while appearing to tighten it.
 */
const STRICTNESS: Record<string, number> = {
  never: 0,
  critical: 1,
  high: 2,
  medium: 3,
  low: 4,
  info: 5,
};

export interface MergedConfig {
  config: AppConfig;
  /** Warnings from parsing, plus any from the merge itself. */
  warnings: string[];
}

export function mergeRepoConfig(base: AppConfig, repo: RepoConfig): MergedConfig {
  const warnings = [...repo.warnings];
  if (!repo.present) return { config: base, warnings };

  const review = { ...base.review };
  const ai = { ...base.ai };

  if (repo.includeTests !== null) review.includeTests = repo.includeTests;
  if (repo.disabledRules.length > 0) {
    review.disabledRules = [...new Set([...review.disabledRules, ...repo.disabledRules])];
  }
  if (repo.minSeverity !== null) review.minSeverity = repo.minSeverity;

  if (repo.failOnSeverity !== null) {
    const current = STRICTNESS[base.review.failOnSeverity] ?? STRICTNESS.high!;
    const requested = STRICTNESS[repo.failOnSeverity] ?? STRICTNESS.high!;
    if (requested >= current) {
      review.failOnSeverity = repo.failOnSeverity;
    } else {
      warnings.push(
        `${repo.sourcePath}: severity.fail-on cannot be looser than the service setting ` +
          `(${base.review.failOnSeverity}); keeping ${base.review.failOnSeverity}. ` +
          'A repository may make the gate stricter, not weaker.',
      );
    }
  }

  if (repo.inline.enabled !== null) review.inlineComments = repo.inline.enabled;
  if (repo.inline.maxComments !== null) review.maxInlineComments = repo.inline.maxComments;
  if (repo.inline.minSeverity !== null) review.inlineMinSeverity = repo.inline.minSeverity;

  // Triage can be switched off locally but not on: turning it on spends the
  // deployment's credential, which is not the repository's to spend.
  if (repo.triage.enabled === false) {
    ai.enabled = false;
  } else if (repo.triage.enabled === true && !base.ai.enabled) {
    warnings.push(
      `${repo.sourcePath}: triage.enabled has no effect because the service has no model configured.`,
    );
  }
  if (repo.triage.minSeverity !== null) ai.minSeverity = repo.triage.minSeverity;

  return { config: { ...base, review, ai }, warnings };
}
