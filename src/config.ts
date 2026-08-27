import { config as loadDotenv } from 'dotenv';
import type { Severity } from './analysis/types';

loadDotenv();

export interface AppConfig {
  port: number;
  /** Public base URL, used to link findings from a PR comment to the dashboard. */
  publicUrl: string;
  github: {
    token: string;
    webhookSecret: string;
    apiBaseUrl: string;
  };
  storage: {
    /** SQLite file path. `:memory:` is supported for tests. */
    databasePath: string;
  };
  review: {
    /** Findings below this severity are never reported. */
    minSeverity: Severity;
    /** Severity at or above which the commit status is reported as failing. */
    failOnSeverity: Severity | 'never';
    /** Cap on findings per file. */
    maxFindingsPerFile: number;
    /** Cap on findings rendered in the PR comment; the rest are summarised. */
    maxFindingsPerComment: number;
    /** Whether test and fixture paths are scanned. */
    includeTests: boolean;
    /** Rule ids or category names to skip. */
    disabledRules: string[];
    /** Skip files larger than this, in bytes. */
    maxFileBytes: number;
    /** Skip pull requests touching more than this many files. */
    maxFilesPerPullRequest: number;
    /** Post findings as inline review comments as well as the summary. */
    inlineComments: boolean;
    /** Cap on inline comments in one review. */
    maxInlineComments: number;
    /** Only findings at or above this severity are posted inline. */
    inlineMinSeverity: Severity;
    /** Upload a SARIF run to code scanning, putting findings in the Security tab. */
    codeScanningUpload: boolean;
  };
  ai: AiConfig;
}

export interface AiConfig {
  /** Triage runs only when a credential and a model are both configured. */
  enabled: boolean;
  apiKey: string;
  /** A model identifier, or `auto` to use the newest the credential can see. */
  model: string;
  baseUrl: string;
  /** Only findings at or above this severity are sent. */
  minSeverity: Severity;
  /** Hard cap per review, so one pull request cannot run up a bill. */
  maxFindings: number;
  /** Lines of context sent on each side of a finding. */
  contextLines: number;
  /** Cap on excerpt lines per file. */
  maxLinesPerFile: number;
  effort: 'low' | 'medium' | 'high' | 'xhigh' | 'max';
  maxTokens: number;
  timeoutMs: number;
  maxRetries: number;
  /**
   * Whether a refuted finding is dropped from the review entirely.
   *
   * Off by default. A refutation is a judgement, and a wrong one would silently
   * hide a real vulnerability - so by default a refuted finding is moved out of
   * the blocking set into a clearly-labelled section where a human still sees
   * it. Turn this on only once you trust the pass on your codebase.
   */
  dropRefuted: boolean;
  /**
   * Replacement HTTP transport for the model API. Not settable from the
   * environment - it exists so an embedder can route through a proxy, and so
   * tests can assert on exactly what would leave the process.
   */
  fetch?: typeof globalThis.fetch;
}

function readInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const value = Number.parseInt(raw, 10);
  return Number.isFinite(value) ? value : fallback;
}

function readBool(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  return /^(1|true|yes|on)$/i.test(raw);
}

function readSeverity(name: string, fallback: Severity): Severity {
  const raw = (process.env[name] ?? '').toLowerCase();
  const allowed: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  return (allowed as string[]).includes(raw) ? (raw as Severity) : fallback;
}

function readList(name: string): string[] {
  return (process.env[name] ?? '')
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

export function loadConfig(): AppConfig {
  const failOn = (process.env.FAIL_ON_SEVERITY ?? 'high').toLowerCase();
  return {
    port: readInt('PORT', 3000),
    publicUrl: (process.env.PUBLIC_URL ?? `http://localhost:${readInt('PORT', 3000)}`).replace(/\/+$/, ''),
    github: {
      token: process.env.GITHUB_TOKEN ?? '',
      webhookSecret: process.env.GITHUB_WEBHOOK_SECRET ?? '',
      apiBaseUrl: process.env.GITHUB_API_URL ?? 'https://api.github.com',
    },
    storage: {
      databasePath: process.env.DATABASE_PATH ?? 'data/reviews.sqlite',
    },
    ai: loadAiConfig(),
    review: {
      minSeverity: readSeverity('MIN_SEVERITY', 'low'),
      failOnSeverity: failOn === 'never' ? 'never' : readSeverity('FAIL_ON_SEVERITY', 'high'),
      maxFindingsPerFile: readInt('MAX_FINDINGS_PER_FILE', 25),
      maxFindingsPerComment: readInt('MAX_FINDINGS_PER_COMMENT', 40),
      includeTests: readBool('INCLUDE_TESTS', false),
      disabledRules: readList('DISABLED_RULES'),
      maxFileBytes: readInt('MAX_FILE_BYTES', 400_000),
      maxFilesPerPullRequest: readInt('MAX_FILES_PER_PR', 300),
      inlineComments: readBool('INLINE_COMMENTS', true),
      maxInlineComments: readInt('MAX_INLINE_COMMENTS', 15),
      inlineMinSeverity: readSeverity('INLINE_MIN_SEVERITY', 'medium'),
      codeScanningUpload: readBool('CODE_SCANNING_UPLOAD', true),
    },
  };
}

function readEffort(): AiConfig['effort'] {
  const raw = (process.env.AI_EFFORT ?? 'high').toLowerCase();
  const allowed: AiConfig['effort'][] = ['low', 'medium', 'high', 'xhigh', 'max'];
  return (allowed as string[]).includes(raw) ? (raw as AiConfig['effort']) : 'high';
}

function loadAiConfig(): AiConfig {
  const apiKey = process.env.ANTHROPIC_API_KEY ?? '';
  const model = process.env.AI_MODEL ?? '';
  return {
    // Both halves are required. A key with no model, or a model with no key, is
    // a half-finished setup and silently running with one is worse than not
    // running at all.
    enabled: readBool('AI_TRIAGE', Boolean(apiKey && model)) && Boolean(apiKey) && Boolean(model),
    apiKey,
    model,
    baseUrl: process.env.AI_BASE_URL ?? '',
    minSeverity: readSeverity('AI_MIN_SEVERITY', 'medium'),
    maxFindings: readInt('AI_MAX_FINDINGS', 25),
    contextLines: readInt('AI_CONTEXT_LINES', 25),
    maxLinesPerFile: readInt('AI_MAX_LINES_PER_FILE', 220),
    effort: readEffort(),
    maxTokens: readInt('AI_MAX_TOKENS', 8000),
    timeoutMs: readInt('AI_TIMEOUT_MS', 120_000),
    maxRetries: readInt('AI_MAX_RETRIES', 2),
    dropRefuted: readBool('AI_DROP_REFUTED', false),
  };
}

/** Config problems that should stop the process rather than surface at request time. */
export function validateConfig(config: AppConfig): string[] {
  const problems: string[] = [];
  if (!config.github.token) {
    problems.push('GITHUB_TOKEN is not set - the reviewer cannot read diffs or post comments.');
  }
  // A half-configured triage setup is the easy mistake to make, and it fails
  // silently: reviews keep working, just without the pass the operator thinks
  // they enabled. Say so at startup.
  if (config.ai.apiKey && !config.ai.model) {
    problems.push(
      'ANTHROPIC_API_KEY is set but AI_MODEL is not, so triage is off. Set AI_MODEL to a model identifier, or to `auto`.',
    );
  }
  if (config.ai.model && !config.ai.apiKey) {
    problems.push('AI_MODEL is set but ANTHROPIC_API_KEY is not, so triage is off.');
  }
  if (!config.github.webhookSecret) {
    problems.push(
      'GITHUB_WEBHOOK_SECRET is not set - webhook payloads cannot be authenticated, so the endpoint would accept forged events.',
    );
  }
  return problems;
}
