import { lowestSatisfyingVersion } from './advisories';
import { clearInjectedAdvisories, parseManifest, setInjectedAdvisories } from './rules/dependencies';
import { lookupAdvisories, type AdvisoryIndex, type OsvOptions, type OsvQuery } from './osv';
import { detectLanguage, isGeneratedPath, isLockfile, isSuppressed, isTestPath } from './source';
import { authenticationRule } from './rules/authentication';
import { authorizationRule } from './rules/authorization';
import { dangerousApiRule } from './rules/dangerous-api';
import { dependenciesRule } from './rules/dependencies';
import { secretsRule } from './rules/secrets';
import { sqlInjectionRule } from './rules/sql-injection';
import {
  emptyCategoryCounts,
  emptySeverityCounts,
  SEVERITY_RANK,
  type Category,
  type Finding,
  type Rule,
  type ScanSummary,
  type ScanTarget,
} from './types';

export const ALL_RULES: Rule[] = [
  sqlInjectionRule,
  authenticationRule,
  secretsRule,
  dependenciesRule,
  authorizationRule,
  dangerousApiRule,
];

export interface EngineOptions {
  /** Categories to run. Omit for all of them. */
  categories?: Category[];
  /** Rule ids (or `category/` prefixes) to skip entirely. */
  disabledRules?: string[];
  /** Findings below this severity are dropped. */
  minSeverity?: Finding['severity'];
  /** Cap on findings per file, so one bad file cannot flood a review. */
  maxFindingsPerFile?: number;
  /** Whether to scan paths that look like tests and fixtures. */
  includeTests?: boolean;
  /**
   * Advisories from a live source, merged with the bundled snapshot. Gathered by
   * `scanWithAdvisories`, which does the asynchronous lookup so the rules
   * themselves stay synchronous.
   */
  advisories?: AdvisoryIndex;
}

const DEFAULT_MAX_PER_FILE = 25;

export interface FileInput {
  filePath: string;
  content: string;
  status: ScanTarget['status'];
  /** `null` scans the whole file; a set restricts reporting to those lines. */
  changedLines: Set<number> | null;
}

export function buildTarget(input: FileInput): ScanTarget {
  return {
    filePath: input.filePath,
    content: input.content,
    lines: input.content.split('\n'),
    language: detectLanguage(input.filePath),
    status: input.status,
    changedLines: input.changedLines,
  };
}

/** Runs every enabled rule over every file and returns a ranked, deduplicated set. */
export function scan(files: FileInput[], options: EngineOptions = {}): ScanSummary {
  const startedAt = Date.now();
  if (options.advisories) setInjectedAdvisories(options.advisories);
  else clearInjectedAdvisories();
  const maxPerFile = options.maxFindingsPerFile ?? DEFAULT_MAX_PER_FILE;
  const minRank = options.minSeverity ? SEVERITY_RANK[options.minSeverity] : SEVERITY_RANK.info;
  const rules = selectRules(options);

  const findings: Finding[] = [];
  const seenFingerprints = new Set<string>();
  let filesScanned = 0;

  for (const input of files) {
    if (input.status === 'removed') continue;
    // Lockfiles are read by the dependency rule via the manifest, not line-scanned.
    if (isLockfile(input.filePath)) continue;
    if (isGeneratedPath(input.filePath)) continue;
    if (!options.includeTests && isTestPath(input.filePath)) continue;

    const target = buildTarget(input);
    filesScanned += 1;

    const fileFindings: Finding[] = [];
    for (const rule of rules) {
      if (rule.skipLanguages?.includes(target.language)) continue;
      if (!rule.languages.includes('*') && !rule.languages.includes(target.language)) continue;
      let produced: Finding[];
      try {
        produced = rule.check(target);
      } catch (error) {
        // A rule throwing must never take the review down: skip it and move on.
        process.emitWarning(
          `rule ${rule.id} failed on ${target.filePath}: ${(error as Error).message}`,
          'RuleFailure',
        );
        continue;
      }
      for (const finding of produced) {
        if (SEVERITY_RANK[finding.severity] > minRank) continue;
        if (isSuppressed(target, finding.line, finding.ruleId)) continue;
        if (seenFingerprints.has(finding.fingerprint)) continue;
        seenFingerprints.add(finding.fingerprint);
        fileFindings.push(finding);
      }
    }

    findings.push(...rank(fileFindings).slice(0, maxPerFile));
  }

  const countsBySeverity = emptySeverityCounts();
  const countsByCategory = emptyCategoryCounts();
  for (const finding of findings) {
    countsBySeverity[finding.severity] += 1;
    countsByCategory[finding.category] += 1;
  }

  return {
    filesScanned,
    findings: rank(findings),
    countsBySeverity,
    countsByCategory,
    durationMs: Date.now() - startedAt,
  };
}

function selectRules(options: EngineOptions): Rule[] {
  const disabled = options.disabledRules ?? [];
  return ALL_RULES.filter((rule) => {
    if (options.categories && !options.categories.includes(rule.category)) return false;
    return !disabled.some((entry) => entry === rule.id || entry === rule.category);
  });
}

const CONFIDENCE_RANK: Record<Finding['confidence'], number> = { high: 0, medium: 1, low: 2 };

/** Worst first, then most-certain first, then by location for a stable order. */
export function rank(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const bySeverity = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    if (bySeverity !== 0) return bySeverity;
    const byConfidence = CONFIDENCE_RANK[a.confidence] - CONFIDENCE_RANK[b.confidence];
    if (byConfidence !== 0) return byConfidence;
    const byPath = a.filePath.localeCompare(b.filePath);
    if (byPath !== 0) return byPath;
    return a.line - b.line;
  });
}

/**
 * Every dependency the given files declare, as advisory queries.
 *
 * Only dependencies with a resolvable concrete version are included: a query
 * needs a version for the source to answer "is this affected", and a range with
 * no floor cannot supply one. The floor of the range is used, matching what the
 * bundled check does - it is the version an install is permitted to resolve to,
 * so it is the version worth asking about.
 */
export function collectAdvisoryQueries(files: FileInput[]): OsvQuery[] {
  const queries: OsvQuery[] = [];
  for (const input of files) {
    if (input.status === 'removed') continue;
    const target = buildTarget(input);
    for (const dependency of parseManifest(target)) {
      const version = lowestSatisfyingVersion(dependency.range);
      if (!version) continue;
      queries.push({ ecosystem: dependency.ecosystem, name: dependency.name, version });
    }
  }
  return queries;
}

export interface ScanWithAdvisoriesResult extends ScanSummary {
  /** How many live advisories were found, and whether the lookup worked. */
  advisoryLookup?: { found: number; cached: number; error?: string; durationMs: number };
}

/**
 * Scans with live advisory data where it is available.
 *
 * The lookup happens once, before any rule runs, so the analyzers stay
 * synchronous and cannot each reach the network. A lookup failure is not a scan
 * failure: the bundled snapshot always applies, so the result is never worse
 * than an offline run.
 */
export async function scanWithAdvisories(
  files: FileInput[],
  options: EngineOptions = {},
  osvOptions?: Partial<OsvOptions> & { enabled?: boolean },
): Promise<ScanWithAdvisoriesResult> {
  if (osvOptions?.enabled === false) return scan(files, options);

  const queries = collectAdvisoryQueries(files);
  if (queries.length === 0) return scan(files, options);

  const { DEFAULT_OSV_OPTIONS } = await import('./osv');
  const lookup = await lookupAdvisories(queries, { ...DEFAULT_OSV_OPTIONS, ...osvOptions });

  const summary = scan(files, { ...options, advisories: lookup.index });
  return {
    ...summary,
    advisoryLookup: {
      found: lookup.found,
      cached: lookup.cached,
      ...(lookup.error ? { error: lookup.error } : {}),
      durationMs: lookup.durationMs,
    },
  };
}

/** Highest severity present, or `null` for a clean scan. */
export function worstSeverity(findings: Finding[]): Finding['severity'] | null {
  if (findings.length === 0) return null;
  return rank(findings)[0]!.severity;
}
