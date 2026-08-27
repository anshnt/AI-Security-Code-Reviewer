import { parse as parseYaml } from 'yaml';
import { CATEGORIES, SEVERITIES, type Category, type Severity } from '../analysis/types';
import { compileGlobs, matchesAny, type CompiledGlob } from './glob';

/**
 * Per-repository configuration.
 *
 * A scanner that can only be tuned by the operator of the service does not
 * survive contact with more than one team: the vendored directory that should be
 * skipped, the rule that is wrong for this codebase, the severity threshold that
 * makes sense for an internal tool but not for a payments API - all of those are
 * facts about a repository, and they belong in the repository.
 *
 * One rule governs the whole design: **the config is read from the base branch,
 * never from the pull request head.** A file on the head is proposed, not
 * agreed. Reading it would let any pull request disable the analyzer that is
 * about to review it - add `rules: { disable: [secrets] }` in the same commit
 * that adds the credential, and the review passes. Reading from the base means a
 * config change has to be merged, which means it has to be reviewed, which is
 * the entire point.
 *
 * Invalid configuration is reported rather than swallowed. A typo that silently
 * disables a rule is a security hole with a friendly face, so unknown keys and
 * bad values become warnings that travel into the pull request comment.
 */

export const CONFIG_PATHS = ['.securityreview.yml', '.securityreview.yaml', '.github/securityreview.yml'];

export interface RepoConfig {
  /** Paths excluded from scanning entirely. */
  excludeGlobs: CompiledGlob[];
  /** When set, only paths matching one of these are scanned. */
  includeGlobs: CompiledGlob[];
  /** Whether test and fixture paths are scanned. */
  includeTests: boolean | null;
  /** Rule ids or category names to skip. */
  disabledRules: string[];
  minSeverity: Severity | null;
  failOnSeverity: Severity | 'never' | null;
  /** Per-rule severity replacement, applied after the analyzers run. */
  severityOverrides: Map<string, Severity>;
  inline: {
    enabled: boolean | null;
    maxComments: number | null;
    minSeverity: Severity | null;
  };
  triage: {
    enabled: boolean | null;
    minSeverity: Severity | null;
  };
  /** Problems found while reading the file, surfaced to the reader. */
  warnings: string[];
  /** True when a config file was found and parsed. */
  present: boolean;
  /** Which path it came from. */
  sourcePath?: string;
}

export function emptyRepoConfig(): RepoConfig {
  return {
    excludeGlobs: [],
    includeGlobs: [],
    includeTests: null,
    disabledRules: [],
    minSeverity: null,
    failOnSeverity: null,
    severityOverrides: new Map(),
    inline: { enabled: null, maxComments: null, minSeverity: null },
    triage: { enabled: null, minSeverity: null },
    warnings: [],
    present: false,
  };
}

const KNOWN_TOP_LEVEL = new Set(['version', 'paths', 'rules', 'severity', 'inline', 'triage']);
const KNOWN_PATHS = new Set(['exclude', 'include', 'include-tests']);
const KNOWN_RULES = new Set(['disable']);
const KNOWN_SEVERITY = new Set(['min', 'fail-on', 'overrides']);
const KNOWN_INLINE = new Set(['enabled', 'max-comments', 'min-severity']);
const KNOWN_TRIAGE = new Set(['enabled', 'min-severity']);

/** Rule ids the engine knows about, for validating `rules.disable`. */
const KNOWN_RULE_PREFIXES = new Set<string>(CATEGORIES as readonly string[]);

export function parseRepoConfig(text: string, sourcePath: string): RepoConfig {
  const config = emptyRepoConfig();
  config.present = true;
  config.sourcePath = sourcePath;

  let document: unknown;
  try {
    document = parseYaml(text);
  } catch (error) {
    config.warnings.push(`${sourcePath} is not valid YAML: ${(error as Error).message}`);
    config.present = false;
    return config;
  }

  if (document === null || document === undefined) {
    // An empty file is a deliberate no-op, not an error.
    return config;
  }
  if (typeof document !== 'object' || Array.isArray(document)) {
    config.warnings.push(`${sourcePath} must contain a mapping at the top level.`);
    config.present = false;
    return config;
  }

  const root = document as Record<string, unknown>;
  warnUnknown(config, root, KNOWN_TOP_LEVEL, sourcePath, '');

  if ('version' in root && root.version !== 1 && root.version !== '1') {
    config.warnings.push(
      `${sourcePath}: version ${String(root.version)} is not recognised; reading it as version 1.`,
    );
  }

  // --- paths ---------------------------------------------------------------
  const paths = asRecord(config, root.paths, sourcePath, 'paths');
  if (paths) {
    warnUnknown(config, paths, KNOWN_PATHS, sourcePath, 'paths');
    config.excludeGlobs = compileGlobs(asStringList(config, paths.exclude, sourcePath, 'paths.exclude'));
    config.includeGlobs = compileGlobs(asStringList(config, paths.include, sourcePath, 'paths.include'));
    config.includeTests = asBoolean(config, paths['include-tests'], sourcePath, 'paths.include-tests');
  }

  // --- rules ---------------------------------------------------------------
  const rules = asRecord(config, root.rules, sourcePath, 'rules');
  if (rules) {
    warnUnknown(config, rules, KNOWN_RULES, sourcePath, 'rules');
    const disabled = asStringList(config, rules.disable, sourcePath, 'rules.disable');
    for (const entry of disabled) {
      // A misspelled rule id disables nothing and looks like it disabled
      // something, which is the worst outcome available - so say so.
      const prefix = entry.split('/')[0] ?? '';
      if (!KNOWN_RULE_PREFIXES.has(prefix)) {
        config.warnings.push(
          `${sourcePath}: rules.disable entry "${entry}" does not name a known category. ` +
            `Categories are: ${[...KNOWN_RULE_PREFIXES].sort().join(', ')}.`,
        );
        continue;
      }
      config.disabledRules.push(entry);
    }
  }

  // --- severity ------------------------------------------------------------
  const severity = asRecord(config, root.severity, sourcePath, 'severity');
  if (severity) {
    warnUnknown(config, severity, KNOWN_SEVERITY, sourcePath, 'severity');
    config.minSeverity = asSeverity(config, severity.min, sourcePath, 'severity.min');
    config.failOnSeverity = asFailOn(config, severity['fail-on'], sourcePath, 'severity.fail-on');

    const overrides = asRecord(config, severity.overrides, sourcePath, 'severity.overrides');
    if (overrides) {
      for (const [ruleId, value] of Object.entries(overrides)) {
        const parsed = asSeverity(config, value, sourcePath, `severity.overrides.${ruleId}`);
        if (parsed) config.severityOverrides.set(ruleId, parsed);
      }
    }
  }

  // --- inline --------------------------------------------------------------
  const inline = asRecord(config, root.inline, sourcePath, 'inline');
  if (inline) {
    warnUnknown(config, inline, KNOWN_INLINE, sourcePath, 'inline');
    config.inline.enabled = asBoolean(config, inline.enabled, sourcePath, 'inline.enabled');
    config.inline.maxComments = asInteger(
      config,
      inline['max-comments'],
      sourcePath,
      'inline.max-comments',
      0,
      100,
    );
    config.inline.minSeverity = asSeverity(
      config,
      inline['min-severity'],
      sourcePath,
      'inline.min-severity',
    );
  }

  // --- triage --------------------------------------------------------------
  const triage = asRecord(config, root.triage, sourcePath, 'triage');
  if (triage) {
    warnUnknown(config, triage, KNOWN_TRIAGE, sourcePath, 'triage');
    config.triage.enabled = asBoolean(config, triage.enabled, sourcePath, 'triage.enabled');
    config.triage.minSeverity = asSeverity(
      config,
      triage['min-severity'],
      sourcePath,
      'triage.min-severity',
    );
  }

  return config;
}

/**
 * Whether a path is in scope. `exclude` always wins over `include`, because a
 * reader who sets both almost certainly means "these, but not those".
 */
export function pathInScope(config: RepoConfig, filePath: string): boolean {
  if (config.excludeGlobs.length > 0 && matchesAny(config.excludeGlobs, filePath)) return false;
  if (config.includeGlobs.length > 0) return matchesAny(config.includeGlobs, filePath);
  return true;
}

// --- Validation helpers -----------------------------------------------------

function warnUnknown(
  config: RepoConfig,
  record: Record<string, unknown>,
  known: Set<string>,
  sourcePath: string,
  prefix: string,
): void {
  for (const key of Object.keys(record)) {
    if (known.has(key)) continue;
    const label = prefix ? `${prefix}.${key}` : key;
    config.warnings.push(
      `${sourcePath}: unknown setting "${label}" - it has no effect. ` +
        `Known keys here: ${[...known].sort().join(', ')}.`,
    );
  }
}

function asRecord(
  config: RepoConfig,
  value: unknown,
  sourcePath: string,
  label: string,
): Record<string, unknown> | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'object' || Array.isArray(value)) {
    config.warnings.push(`${sourcePath}: ${label} must be a mapping; ignoring it.`);
    return null;
  }
  return value as Record<string, unknown>;
}

function asStringList(
  config: RepoConfig,
  value: unknown,
  sourcePath: string,
  label: string,
): string[] {
  if (value === undefined || value === null) return [];
  if (typeof value === 'string') return [value];
  if (!Array.isArray(value)) {
    config.warnings.push(`${sourcePath}: ${label} must be a list of strings; ignoring it.`);
    return [];
  }
  const out: string[] = [];
  for (const entry of value) {
    if (typeof entry === 'string') out.push(entry);
    else config.warnings.push(`${sourcePath}: ${label} contains a non-string entry; ignoring it.`);
  }
  return out;
}

function asBoolean(
  config: RepoConfig,
  value: unknown,
  sourcePath: string,
  label: string,
): boolean | null {
  if (value === undefined || value === null) return null;
  if (typeof value === 'boolean') return value;
  config.warnings.push(`${sourcePath}: ${label} must be true or false; ignoring it.`);
  return null;
}

function asInteger(
  config: RepoConfig,
  value: unknown,
  sourcePath: string,
  label: string,
  min: number,
  max: number,
): number | null {
  if (value === undefined || value === null) return null;
  const parsed = typeof value === 'number' ? value : Number.parseInt(String(value), 10);
  if (!Number.isFinite(parsed) || !Number.isInteger(parsed)) {
    config.warnings.push(`${sourcePath}: ${label} must be a whole number; ignoring it.`);
    return null;
  }
  if (parsed < min || parsed > max) {
    config.warnings.push(
      `${sourcePath}: ${label} must be between ${min} and ${max}; ignoring ${parsed}.`,
    );
    return null;
  }
  return parsed;
}

function asSeverity(
  config: RepoConfig,
  value: unknown,
  sourcePath: string,
  label: string,
): Severity | null {
  if (value === undefined || value === null) return null;
  const raw = String(value).toLowerCase();
  if ((SEVERITIES as readonly string[]).includes(raw)) return raw as Severity;
  config.warnings.push(
    `${sourcePath}: ${label} must be one of ${SEVERITIES.join(', ')}; ignoring "${String(value)}".`,
  );
  return null;
}

function asFailOn(
  config: RepoConfig,
  value: unknown,
  sourcePath: string,
  label: string,
): Severity | 'never' | null {
  if (value === undefined || value === null) return null;
  const raw = String(value).toLowerCase();
  if (raw === 'never') return 'never';
  return asSeverity(config, value, sourcePath, label);
}

export type { Category };
