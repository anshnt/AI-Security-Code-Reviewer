#!/usr/bin/env node
import { existsSync, readFileSync } from 'node:fs';
import { scan } from '../analysis/engine';
import type { ScanSummary } from '../analysis/types';
import { CONFIG_PATHS, emptyRepoConfig, parseRepoConfig, type RepoConfig } from '../config/repo-config';
import { HELP_TEXT, parseArgs, type CliOptions } from './args';
import { collectFromDiff, collectFromPaths, type CollectResult } from './collect';
import { countBlocking, renderJson, renderPretty, renderRules, shouldUseColor } from './report';

/**
 * The local entry point.
 *
 * The reason this exists is that a finding is cheapest to fix before it is
 * pushed, and free to fix before it is written. The analyzers, the rule set and
 * the config file are all shared with the pull-request reviewer, so what runs
 * here is what will run in CI - a local check that disagrees with CI is worse
 * than no local check, because it teaches people to distrust both.
 *
 * Exit status is the contract:
 *   0  nothing at or above --fail-on
 *   1  findings at or above --fail-on
 *   2  the command could not run
 *
 * The distinction between 1 and 2 matters in a pre-commit hook or a pipeline
 * step. "Found problems" and "could not look" call for different responses, and
 * collapsing them means a broken invocation reads as a clean run.
 */

const EXIT_CLEAN = 0;
const EXIT_FINDINGS = 1;
const EXIT_ERROR = 2;

const MAX_FILE_BYTES = 400_000;

export function run(argv: readonly string[]): number {
  const parsed = parseArgs(argv);
  if (parsed.error || !parsed.options) {
    process.stderr.write(`security-review: ${parsed.error ?? 'could not parse arguments'}\n`);
    return EXIT_ERROR;
  }
  const options = parsed.options;
  const color = shouldUseColor(options.color);

  if (options.command === 'help') {
    process.stdout.write(HELP_TEXT);
    return EXIT_CLEAN;
  }
  if (options.command === 'version') {
    process.stdout.write(`${readVersion()}\n`);
    return EXIT_CLEAN;
  }
  if (options.command === 'rules') {
    process.stdout.write(`${renderRules(color)}\n`);
    return EXIT_CLEAN;
  }

  const { repoConfig, error: configError } = loadConfigFile(options);
  if (configError) {
    process.stderr.write(`security-review: ${configError}\n`);
    return EXIT_ERROR;
  }

  const collected = collect(options, repoConfig);
  if (collected.error) {
    process.stderr.write(`security-review: ${collected.error}\n`);
    return EXIT_ERROR;
  }

  const summary = scan(collected.files, {
    minSeverity: repoConfig.minSeverity ?? options.minSeverity,
    includeTests: repoConfig.includeTests ?? options.includeTests,
    disabledRules: [...options.disabledRules, ...repoConfig.disabledRules],
  });

  const rescored = applyOverrides(summary, repoConfig);
  const failOn = repoConfig.failOnSeverity ?? options.failOn;

  const reportOptions = {
    color,
    limit: options.limit,
    quiet: options.quiet,
    failOn,
    skipped: collected.skipped,
    configWarnings: repoConfig.warnings,
    scope: collected.scope,
  };

  process.stdout.write(
    `${options.format === 'json' ? renderJson(rescored, reportOptions) : renderPretty(rescored, reportOptions)}\n`,
  );

  return countBlocking(rescored.findings, failOn) > 0 ? EXIT_FINDINGS : EXIT_CLEAN;
}

interface Collected extends CollectResult {
  scope: string;
  error?: string;
}

function collect(options: CliOptions, repoConfig: RepoConfig): Collected {
  const collectOptions = { maxFileBytes: MAX_FILE_BYTES, repoConfig };

  if (options.diffAgainst !== null) {
    const result = collectFromDiff(options.diffAgainst, collectOptions);
    return {
      ...result,
      scope: `changed lines against ${options.diffAgainst}`,
    };
  }

  const result = collectFromPaths(options.paths, collectOptions);
  return {
    ...result,
    scope: options.paths.length === 1 && options.paths[0] === '.'
      ? 'working tree'
      : options.paths.join(', '),
  };
}

/**
 * Finds the config file, or reports that an explicitly named one is missing.
 *
 * A `--config` path that does not exist is an error rather than a fallback: the
 * user said which file to use, and silently reviewing with different settings
 * than they asked for is how a gating check stops gating.
 */
function loadConfigFile(options: CliOptions): { repoConfig: RepoConfig; error?: string } {
  if (options.noConfig) return { repoConfig: emptyRepoConfig() };

  if (options.configPath) {
    if (!existsSync(options.configPath)) {
      return { repoConfig: emptyRepoConfig(), error: `no such config file: ${options.configPath}` };
    }
    return {
      repoConfig: parseRepoConfig(readFileSync(options.configPath, 'utf8'), options.configPath),
    };
  }

  for (const path of CONFIG_PATHS) {
    if (!existsSync(path)) continue;
    return { repoConfig: parseRepoConfig(readFileSync(path, 'utf8'), path) };
  }
  return { repoConfig: emptyRepoConfig() };
}

function applyOverrides(summary: ScanSummary, repoConfig: RepoConfig): ScanSummary {
  if (repoConfig.severityOverrides.size === 0) return summary;
  const findings = summary.findings.map((finding) => {
    const override =
      repoConfig.severityOverrides.get(finding.ruleId) ??
      repoConfig.severityOverrides.get(finding.category);
    return override ? { ...finding, severity: override } : finding;
  });
  const countsBySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) countsBySeverity[finding.severity] += 1;
  return { ...summary, findings, countsBySeverity };
}

function readVersion(): string {
  try {
    // Resolved relative to the compiled file, so it works from dist/ too.
    const packageJson = JSON.parse(
      readFileSync(new URL('../../package.json', `file://${__filename}`), 'utf8'),
    ) as { version?: string };
    return packageJson.version ?? 'unknown';
  } catch {
    return 'unknown';
  }
}

// Only act as a program when invoked as one, so the module stays importable by
// the tests without exiting the process.
if (require.main === module) {
  process.exitCode = run(process.argv.slice(2));
}
