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
  };
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
    review: {
      minSeverity: readSeverity('MIN_SEVERITY', 'low'),
      failOnSeverity: failOn === 'never' ? 'never' : readSeverity('FAIL_ON_SEVERITY', 'high'),
      maxFindingsPerFile: readInt('MAX_FINDINGS_PER_FILE', 25),
      maxFindingsPerComment: readInt('MAX_FINDINGS_PER_COMMENT', 40),
      includeTests: readBool('INCLUDE_TESTS', false),
      disabledRules: readList('DISABLED_RULES'),
      maxFileBytes: readInt('MAX_FILE_BYTES', 400_000),
      maxFilesPerPullRequest: readInt('MAX_FILES_PER_PR', 300),
    },
  };
}

/** Config problems that should stop the process rather than surface at request time. */
export function validateConfig(config: AppConfig): string[] {
  const problems: string[] = [];
  if (!config.github.token) {
    problems.push('GITHUB_TOKEN is not set - the reviewer cannot read diffs or post comments.');
  }
  if (!config.github.webhookSecret) {
    problems.push(
      'GITHUB_WEBHOOK_SECRET is not set - webhook payloads cannot be authenticated, so the endpoint would accept forged events.',
    );
  }
  return problems;
}
