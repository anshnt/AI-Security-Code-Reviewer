/**
 * Core vocabulary shared by every analyzer, the persistence layer and the
 * dashboard. Keeping these definitions in one place means a new rule only has
 * to declare which category and severity it belongs to.
 */

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const CATEGORIES = [
  'sql-injection',
  'authentication',
  'secrets',
  'dependencies',
  'authorization',
  'dangerous-api',
] as const;
export type Category = (typeof CATEGORIES)[number];

export const CATEGORY_LABELS: Record<Category, string> = {
  'sql-injection': 'SQL Injection',
  authentication: 'Authentication',
  secrets: 'Secrets',
  dependencies: 'Dependencies',
  authorization: 'Authorization',
  'dangerous-api': 'Dangerous APIs',
};

/** Ordering helper so findings always surface worst-first. */
export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export type Confidence = 'high' | 'medium' | 'low';

export interface Finding {
  /** Stable rule identifier, e.g. `sql-injection/string-concatenation`. */
  ruleId: string;
  category: Category;
  severity: Severity;
  confidence: Confidence;
  /** One-line headline shown in the PR comment table. */
  title: string;
  /** Why this is a problem, in reviewer voice. */
  description: string;
  /** Concrete, actionable fix. */
  remediation: string;
  filePath: string;
  /** 1-based line number in the post-change version of the file. */
  line: number;
  endLine?: number;
  /** The offending source line, trimmed and truncated. */
  snippet: string;
  cwe?: string[];
  /**
   * Content-addressed identity of the finding. Survives line movement so the
   * same issue is not reported as "new" on every push.
   */
  fingerprint: string;
}

/** What a rule receives: the full post-change file plus which lines the PR touched. */
export interface ScanTarget {
  filePath: string;
  content: string;
  /** Pre-split lines of `content` (0-indexed; line N is `lines[N - 1]`). */
  lines: string[];
  language: Language;
  status: 'added' | 'modified' | 'renamed' | 'removed';
  /**
   * Line numbers the pull request added or changed. `null` means "the whole
   * file is in scope" (local CLI scans, newly added files).
   */
  changedLines: Set<number> | null;
}

export const LANGUAGES = [
  'javascript',
  'typescript',
  'python',
  'java',
  'go',
  'ruby',
  'php',
  'csharp',
  'sql',
  'yaml',
  'json',
  'terraform',
  'shell',
  'documentation',
  'other',
] as const;
export type Language = (typeof LANGUAGES)[number];

export interface Rule {
  id: string;
  category: Category;
  /** Human-readable purpose, surfaced in `--list-rules` and the docs. */
  description: string;
  /** Languages the rule understands. `['*']` means language-agnostic. */
  languages: readonly (Language | '*')[];
  /**
   * Languages this rule must never run against, even when otherwise
   * language-agnostic. Prose that *describes* `eval` is not a call to `eval`,
   * so the code-analysis rules opt out of documentation while the secrets rule
   * deliberately keeps running - a key pasted into a README is a real key.
   */
  skipLanguages?: readonly Language[];
  check(target: ScanTarget): Finding[];
}

export interface ScanSummary {
  filesScanned: number;
  findings: Finding[];
  countsBySeverity: Record<Severity, number>;
  countsByCategory: Record<Category, number>;
  durationMs: number;
}

export function emptySeverityCounts(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

export function emptyCategoryCounts(): Record<Category, number> {
  return {
    'sql-injection': 0,
    authentication: 0,
    secrets: 0,
    dependencies: 0,
    authorization: 0,
    'dangerous-api': 0,
  };
}
