import { createHash } from 'node:crypto';
import type { Finding, Language, ScanTarget } from './types';

const EXTENSION_LANGUAGES: Record<string, Language> = {
  js: 'javascript',
  jsx: 'javascript',
  mjs: 'javascript',
  cjs: 'javascript',
  ts: 'typescript',
  tsx: 'typescript',
  mts: 'typescript',
  cts: 'typescript',
  py: 'python',
  pyi: 'python',
  java: 'java',
  go: 'go',
  rb: 'ruby',
  erb: 'ruby',
  php: 'php',
  cs: 'csharp',
  sql: 'sql',
  yml: 'yaml',
  yaml: 'yaml',
  json: 'json',
  tf: 'terraform',
  tfvars: 'terraform',
  sh: 'shell',
  bash: 'shell',
  zsh: 'shell',
  md: 'documentation',
  markdown: 'documentation',
  mdx: 'documentation',
  rst: 'documentation',
  adoc: 'documentation',
  // An SVG is an image: its text nodes are labels, so line-scanning them for
  // code sinks finds only the words in a diagram. The secrets rule still runs
  // against it, because a credential embedded in an asset is still a credential.
  svg: 'documentation',
  // `.txt` is deliberately absent: requirements.txt and constraints.txt are
  // dependency manifests, and classifying them as prose would stop the
  // dependency rule from ever seeing them.
};

export function detectLanguage(filePath: string): Language {
  const base = filePath.split('/').pop() ?? filePath;
  const ext = base.includes('.') ? base.split('.').pop()!.toLowerCase() : '';
  return EXTENSION_LANGUAGES[ext] ?? 'other';
}

/** JS/TS-family languages share almost all of their dangerous idioms. */
export function isJsFamily(language: Language): boolean {
  return language === 'javascript' || language === 'typescript';
}

const GENERATED_PATH = /(^|\/)(node_modules|vendor|dist|build|out|coverage|\.next|__snapshots__)\//;
const MINIFIED_NAME = /\.(min|bundle)\.(js|css)$/;
const LOCKFILE_NAME =
  /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Gemfile\.lock|composer\.lock|go\.sum|Cargo\.lock)$/;

/**
 * Files whose contents are machine-produced. We still want to know *that* they
 * changed (the dependency rules read lockfiles), but we never line-scan them.
 */
export function isGeneratedPath(filePath: string): boolean {
  return GENERATED_PATH.test(filePath) || MINIFIED_NAME.test(filePath);
}

export function isLockfile(filePath: string): boolean {
  return LOCKFILE_NAME.test(filePath);
}

const TEST_PATH =
  /(^|\/)(tests?|specs?|__tests__|__mocks__|e2e|fixtures?|testdata)\/|[.\-_](test|spec|fixture|mock)\.[a-z]+$/i;

/** Test and fixture files legitimately contain fake credentials and unsafe demos. */
export function isTestPath(filePath: string): boolean {
  return TEST_PATH.test(filePath);
}

export function truncate(text: string, max = 200): string {
  const flat = text.replace(/\s+/g, ' ').trim();
  return flat.length > max ? `${flat.slice(0, max - 3)}...` : flat;
}

/**
 * Identity of a finding, independent of the line it currently sits on. Built
 * from the rule, the path and the normalized source text so that reformatting
 * or moving code does not resurrect an already-triaged finding.
 */
export function fingerprint(ruleId: string, filePath: string, evidence: string): string {
  const normalized = evidence.replace(/\s+/g, ' ').trim();
  // security-review-ignore-next-line authentication/weak-password-hash
  // SHA-256 is the right tool here: this is a content address for deduplication,
  // not a credential hash, so speed is a feature and there is nothing to brute-force.
  return createHash('sha256')
    .update(`${ruleId} ${filePath} ${normalized}`)
    .digest('hex')
    .slice(0, 20);
}

// The `(?![\w-])` guard stops this from also matching `-file`, whose rule list
// would otherwise be read as a line-level waiver and defeat the header-only rule.
const SUPPRESSION = /security-review-ignore(?:-next-line)?(?![\w-])(?::?[ \t]*([a-z0-9/,\-* \t]+))?/i;
const FILE_SUPPRESSION = /security-review-ignore-file(?::?[ \t]*([a-z0-9/,\-* \t]+))?/i;
/** Only a header comment can waive a whole file, so a directive cannot hide in the middle of one. */
const FILE_SUPPRESSION_SCAN_LINES = 30;
/** Bound on the comment block searched above a flagged line. */
const MAX_SUPPRESSION_LOOKBACK = 6;

/**
 * Honours inline waivers. Both forms are accepted:
 *   `// security-review-ignore-next-line sql-injection/string-concatenation`
 *   `foo(bar) // security-review-ignore`
 * Omitting the rule list suppresses every rule on that line.
 */
export function isSuppressed(target: ScanTarget, line: number, ruleId: string): boolean {
  if (isFileSuppressed(target, ruleId)) return true;

  // The flagged line itself, then the comment block directly above it. Walking
  // the whole block rather than a fixed one line back means the directive can be
  // followed by the explanation of *why* it is there, which is the form worth
  // encouraging.
  const candidates: (string | undefined)[] = [target.lines[line - 1]];
  for (let above = line - 2; above >= 0; above -= 1) {
    const text = target.lines[above];
    if (text === undefined || !isCommentLine(text)) break;
    candidates.push(text);
    if (candidates.length > MAX_SUPPRESSION_LOOKBACK) break;
  }

  for (const candidate of candidates) {
    if (!candidate) continue;
    const match = SUPPRESSION.exec(candidate);
    if (!match) continue;
    const list = match[1]?.trim();
    if (!list) return true;
    const wanted = list.split(/[,\s]+/).filter(Boolean);
    if (wanted.some((entry) => entry === '*' || entry === ruleId || ruleId.startsWith(`${entry}/`))) {
      return true;
    }
  }
  return false;
}

/**
 * Waives rules for an entire file via a header directive:
 *   `security-review-ignore-file dangerous-api, sql-injection`
 *
 * This exists for files whose *content is data about* dangerous code rather
 * than dangerous code - rule tables, pattern fixtures, documentation of unsafe
 * examples - where a per-line waiver on every entry is noise. Only the first
 * few lines are searched, so the directive has to be a deliberate header rather
 * than something buried mid-file.
 */
export function isFileSuppressed(target: ScanTarget, ruleId: string): boolean {
  const header = target.lines.slice(0, FILE_SUPPRESSION_SCAN_LINES);
  for (const line of header) {
    const match = FILE_SUPPRESSION.exec(line);
    if (!match) continue;
    const list = match[1]?.trim();
    // An unqualified file-level waiver would silence everything, which is too
    // blunt to allow by accident - require an explicit rule or category list.
    if (!list) continue;
    const wanted = list.split(/[,\s]+/).filter(Boolean);
    if (wanted.some((entry) => entry === '*' || entry === ruleId || ruleId.startsWith(`${entry}/`))) {
      return true;
    }
  }
  return false;
}

/** Shannon entropy in bits per character - the standard secret-detection signal. */
export function shannonEntropy(value: string): number {
  if (!value) return 0;
  const counts = new Map<string, number>();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Rewrites compound identifiers so word-boundary patterns can see inside them:
 * `resetToken` becomes `reset Token`, `api_key` becomes `api key`. Without this,
 * a context check for `\btoken\b` misses `resetToken` entirely - which is
 * exactly where the interesting names live.
 */
export function splitIdentifiers(text: string): string {
  return text
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .replace(/[_\-]+/g, ' ');
}

const LINE_COMMENT = /^\s*(\/\/|#|--|\*|\/\*)/;

export function isCommentLine(line: string): boolean {
  return LINE_COMMENT.test(line);
}

/**
 * Replaces string literal *bodies* with spaces while preserving length and
 * quote positions. Lets structural checks (does this line concatenate a
 * variable?) ignore text that merely mentions a keyword.
 */
export function blankStringLiterals(line: string): string {
  let out = '';
  let quote: string | null = null;
  for (let i = 0; i < line.length; i += 1) {
    const char = line[i]!;
    if (quote) {
      if (char === '\\') {
        out += '  ';
        i += 1;
        continue;
      }
      if (char === quote) {
        quote = null;
        out += char;
        continue;
      }
      out += ' ';
      continue;
    }
    if (char === '"' || char === "'" || char === '`') {
      quote = char;
      out += char;
      continue;
    }
    out += char;
  }
  return out;
}

/** Extracts every quoted literal on a line, without the surrounding quotes. */
export function stringLiterals(line: string): string[] {
  const out: string[] = [];
  const pattern = /(["'`])((?:\\.|(?!\1)[^\\])*)\1/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(line))) {
    if (match[2]) out.push(match[2]);
  }
  return out;
}

/**
 * The enclosing block of a line, used by rules that need surrounding context
 * (an ownership check elsewhere in the same handler, for example).
 */
export function enclosingBlock(target: ScanTarget, line: number, maxSpan = 60): string {
  const start = Math.max(0, line - 1 - maxSpan);
  const end = Math.min(target.lines.length, line + maxSpan);
  return target.lines.slice(start, end).join('\n');
}

export interface FindingDraft {
  ruleId: string;
  severity: Finding['severity'];
  confidence: Finding['confidence'];
  title: string;
  description: string;
  remediation: string;
  line: number;
  endLine?: number;
  evidence: string;
  cwe?: string[];
  /**
   * Extra text mixed into the fingerprint but not shown in the snippet.
   *
   * Needed when several distinct findings share one source line - four published
   * advisories against the same dependency, for example. Without it they all
   * fingerprint identically and the engine's deduplication silently keeps one,
   * reporting a single advisory where four exist.
   */
  fingerprintExtra?: string;
}

/** Builds a complete `Finding` from the fields a rule actually cares about. */
export function makeFinding(
  target: ScanTarget,
  category: Finding['category'],
  draft: FindingDraft,
): Finding {
  const snippet = truncate(draft.evidence);
  return {
    ruleId: draft.ruleId,
    category,
    severity: draft.severity,
    confidence: draft.confidence,
    title: draft.title,
    description: draft.description,
    remediation: draft.remediation,
    filePath: target.filePath,
    line: draft.line,
    ...(draft.endLine ? { endLine: draft.endLine } : {}),
    snippet,
    ...(draft.cwe ? { cwe: draft.cwe } : {}),
    fingerprint: fingerprint(
      draft.ruleId,
      target.filePath,
      draft.fingerprintExtra ? `${snippet} ${draft.fingerprintExtra}` : snippet,
    ),
  };
}
