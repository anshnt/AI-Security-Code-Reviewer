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

/** Highest severity present, or `null` for a clean scan. */
export function worstSeverity(findings: Finding[]): Finding['severity'] | null {
  if (findings.length === 0) return null;
  return rank(findings)[0]!.severity;
}
