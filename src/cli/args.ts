import { SEVERITIES, type Severity } from '../analysis/types';

/**
 * Argument parsing.
 *
 * Hand-rolled rather than delegated, for the same reason the glob matcher is:
 * the surface is a dozen flags, and a parser dependency brings its own
 * conventions for things like `--` handling and abbreviation that then have to
 * be documented alongside ours.
 *
 * Unknown flags are an error, not a warning. A mistyped `--fail-on` that is
 * silently ignored turns a gating check into a no-op, which is the failure mode
 * this whole tool exists to prevent.
 */

export interface CliOptions {
  command: 'scan' | 'rules' | 'help' | 'version';
  /** Files and directories to scan. Defaults to the working directory. */
  paths: string[];
  /** When set, scan only what changed against this git ref. */
  diffAgainst: string | null;
  format: 'pretty' | 'json';
  /** Exit non-zero when a finding at or above this severity is present. */
  failOn: Severity | 'never';
  /** Findings below this are not reported at all. */
  minSeverity: Severity;
  /** Path to a `.securityreview.yml`, or null to look for one automatically. */
  configPath: string | null;
  /** Skip the automatic config lookup entirely. */
  noConfig: boolean;
  includeTests: boolean;
  disabledRules: string[];
  color: boolean | null;
  /** Cap on findings printed; the rest are summarised. */
  limit: number;
  quiet: boolean;
}

export interface ParseResult {
  options?: CliOptions;
  error?: string;
}

const DEFAULTS: CliOptions = {
  command: 'scan',
  paths: [],
  diffAgainst: null,
  format: 'pretty',
  failOn: 'high',
  minSeverity: 'low',
  configPath: null,
  noConfig: false,
  includeTests: false,
  disabledRules: [],
  color: null,
  limit: 50,
  quiet: false,
};

export function parseArgs(argv: readonly string[]): ParseResult {
  const options: CliOptions = { ...DEFAULTS, paths: [], disabledRules: [] };
  let sawCommand = false;
  let onlyPositional = false;

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]!;

    if (onlyPositional) {
      options.paths.push(arg);
      continue;
    }
    if (arg === '--') {
      onlyPositional = true;
      continue;
    }

    if (!arg.startsWith('-')) {
      if (!sawCommand && (arg === 'scan' || arg === 'rules' || arg === 'help')) {
        options.command = arg;
        sawCommand = true;
        continue;
      }
      options.paths.push(arg);
      continue;
    }

    const [flag, inlineValue] = splitFlag(arg);
    const takeValue = (): string | null => {
      if (inlineValue !== null) return inlineValue;
      const next = argv[index + 1];
      if (next === undefined || next.startsWith('-')) return null;
      index += 1;
      return next;
    };

    switch (flag) {
      case '-h':
      case '--help':
        options.command = 'help';
        break;
      case '-v':
      case '--version':
        options.command = 'version';
        break;
      case '--list-rules':
        options.command = 'rules';
        break;
      case '--diff': {
        // `--diff` with no value means "against the default base", which is the
        // overwhelmingly common case and not worth making people type.
        options.diffAgainst = takeValue() ?? 'HEAD';
        break;
      }
      case '--format': {
        const value = takeValue();
        if (value !== 'pretty' && value !== 'json') {
          return { error: `--format must be pretty or json, not ${String(value)}` };
        }
        options.format = value;
        break;
      }
      case '--fail-on': {
        const value = (takeValue() ?? '').toLowerCase();
        if (value !== 'never' && !isSeverity(value)) {
          return { error: `--fail-on must be never or one of ${SEVERITIES.join(', ')}` };
        }
        options.failOn = value === 'never' ? 'never' : (value as Severity);
        break;
      }
      case '--min-severity': {
        const value = (takeValue() ?? '').toLowerCase();
        if (!isSeverity(value)) {
          return { error: `--min-severity must be one of ${SEVERITIES.join(', ')}` };
        }
        options.minSeverity = value as Severity;
        break;
      }
      case '--config': {
        const value = takeValue();
        if (!value) return { error: '--config needs a path' };
        options.configPath = value;
        break;
      }
      case '--no-config':
        options.noConfig = true;
        break;
      case '--include-tests':
        options.includeTests = true;
        break;
      case '--disable': {
        const value = takeValue();
        if (!value) return { error: '--disable needs a rule id or category' };
        options.disabledRules.push(...value.split(',').map((entry) => entry.trim()).filter(Boolean));
        break;
      }
      case '--limit': {
        const value = Number.parseInt(takeValue() ?? '', 10);
        if (!Number.isFinite(value) || value < 1) {
          return { error: '--limit needs a positive whole number' };
        }
        options.limit = value;
        break;
      }
      case '--color':
        options.color = true;
        break;
      case '--no-color':
        options.color = false;
        break;
      case '--quiet':
      case '-q':
        options.quiet = true;
        break;
      default:
        return { error: `unknown option ${flag}. Run with --help to see what is available.` };
    }
  }

  if (options.paths.length === 0) options.paths.push('.');
  return { options };
}

function splitFlag(arg: string): [string, string | null] {
  const equals = arg.indexOf('=');
  if (equals < 0) return [arg, null];
  return [arg.slice(0, equals), arg.slice(equals + 1)];
}

function isSeverity(value: string): boolean {
  return (SEVERITIES as readonly string[]).includes(value);
}

export const HELP_TEXT = `security-review - security analysis for a working tree or a diff

Usage
  security-review [scan] [paths...] [options]
  security-review --list-rules
  security-review --help

Scanning
  paths...                Files or directories to scan. Default: the working directory.
  --diff [ref]            Scan only lines changed against a git ref, the way the
                          pull-request reviewer does. Default ref: HEAD.
  --include-tests         Also scan test and fixture paths, which are skipped by
                          default because they legitimately contain fake
                          credentials and deliberately unsafe examples.
  --disable <list>        Comma-separated rule ids or categories to skip.
  --min-severity <level>  Do not report below this level. Default: low.

Output
  --format <pretty|json>  Default: pretty.
  --limit <n>             Findings to print in full. Default: 50.
  --color / --no-color    Override colour detection.
  --quiet, -q             Print only the summary line.

Exit status
  --fail-on <level>       Exit 1 when a finding at or above this level is found.
                          Use "never" to always exit 0. Default: high.

  0   nothing at or above --fail-on
  1   findings at or above --fail-on
  2   the command could not run

Configuration
  --config <path>         Read settings from this .securityreview.yml.
  --no-config             Ignore any config file found automatically.

Examples
  security-review                             scan the working tree
  security-review --diff origin/main          scan what this branch changed
  security-review src/ --fail-on critical     gate on critical only
  security-review --format json | jq .        machine-readable output
`;
