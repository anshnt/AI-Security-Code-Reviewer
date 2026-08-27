import type { ScanTarget } from './types';

/**
 * Lightweight, single-file taint reasoning.
 *
 * A full dataflow analysis needs a parser per language and a call graph. That
 * is the wrong trade for a pull-request reviewer: we want *no* setup, every
 * language, and an answer in milliseconds. So instead we do what an
 * experienced reviewer does when skimming a diff - look for expressions that
 * are obviously request-derived, follow them through straight-line variable
 * assignments in the same file, and use that to decide whether a risky sink is
 * probably reachable by an attacker.
 *
 * The output is a *confidence signal*, never a proof. Rules combine it with
 * their own structural evidence.
 */

/** Expressions that read attacker-controlled data, across the supported stacks. */
const SOURCE_PATTERNS: RegExp[] = [
  // Express / Koa / Fastify / Next.js
  /\breq(?:uest)?\s*\.\s*(?:body|query|params|param|cookies|headers|header|files|file|url|originalUrl|hostname|ip)\b/,
  /\bctx\s*\.\s*(?:request\s*\.\s*)?(?:body|query|params|querystring|headers)\b/,
  /\bsearchParams\s*\.\s*get\s*\(/,
  /\bnew\s+URLSearchParams\s*\(/,
  // Browser-side sources
  /\b(?:document\s*\.\s*(?:location|referrer|cookie|URL)|window\s*\.\s*(?:location|name))\b/,
  /\blocation\s*\.\s*(?:hash|search|href|pathname)\b/,
  // Python: Flask / Django / FastAPI
  /\brequest\s*\.\s*(?:args|form|json|data|values|files|cookies|headers|GET|POST|body|query_params|path_params)\b/,
  /\bself\s*\.\s*request\s*\.\s*(?:GET|POST|body|args)\b/,
  // Java / Spring
  /\b(?:request|req)\s*\.\s*get(?:Parameter|ParameterValues|Header|Cookies|QueryString|InputStream|Reader)\s*\(/,
  /@(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|ModelAttribute)\b/,
  // Go
  /\br\s*\.\s*(?:URL\s*\.\s*Query\s*\(\s*\)|FormValue|PostFormValue|Header\s*\.\s*Get|Body)\b/,
  /\bmux\s*\.\s*Vars\s*\(/,
  // PHP
  /\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b/,
  /\bphp:\/\/input\b/,
  // Ruby / Rails
  /\bparams\s*\[/,
  // C# / ASP.NET
  /\bRequest\s*\.\s*(?:Query|Form|Cookies|Headers|Body|QueryString|Params)\b/,
  // CLI arguments and stdin are attacker-controlled for many services
  /\bprocess\s*\.\s*argv\b/,
  /\bsys\s*\.\s*argv\b/,
];

/** Names that all but announce that a value came from outside the process. */
const SOURCE_NAME_HINTS =
  /\b(?:user|users?_?input|userinput|payload|body|params?|query|search|filter|term|keyword|slug|email|username|name|id|ids|order_?by|sort|column|table|path|file(?:name|path)?|url|uri|redirect|next|callback|host|domain|cmd|command|arg|args|data|raw|untrusted|external|client|request)\b/i;

/**
 * Shell-only sources. A script's positional parameters and anything read from
 * stdin are external input, but `$1` also appears in JavaScript replacement
 * strings and Java placeholders, so these patterns are scoped to shell files
 * rather than added to the language-agnostic list.
 */
const SHELL_SOURCE_PATTERNS: RegExp[] = [
  /\$\{?[1-9][0-9]?\}?/,
  /\$[@*]/,
  /\$\{?(?:QUERY_STRING|REQUEST_URI|HTTP_[A-Z_]+|REMOTE_ADDR)\}?/,
  /\bread\s+(?:-[a-z]+\s+)*[A-Za-z_]/,
];

export function isDirectUserInput(expression: string): boolean {
  return SOURCE_PATTERNS.some((pattern) => pattern.test(expression));
}

/** Language-aware source test, used by the per-file taint map. */
function directSourceFor(language: ScanTarget['language']): (expression: string) => boolean {
  if (language !== 'shell') return isDirectUserInput;
  return (expression: string) =>
    isDirectUserInput(expression) || SHELL_SOURCE_PATTERNS.some((pattern) => pattern.test(expression));
}

export function looksLikeUserInputName(identifier: string): boolean {
  return SOURCE_NAME_HINTS.test(identifier);
}

/**
 * Matches an assignment and captures the declared name plus the initializer,
 * covering `const a = ...`, `a = ...`, `a: Type = ...`, `var a := ...`,
 * `String a = ...` and `$a = ...`.
 */
const ASSIGNMENT =
  /(?:^|[;{}]|\bconst\b|\blet\b|\bvar\b|\bfinal\b)\s*\$?([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*[A-Za-z0-9_<>,\[\]. ?|]+)?\s*(?::?=)\s*([^;]*)/;

/** Destructuring: `const { id, name } = req.params`. */
const DESTRUCTURE =
  /(?:const|let|var)?\s*\{\s*([^}]*)\}\s*=\s*(.+)$/;

export interface TaintMap {
  /** Variable names that hold - directly or transitively - request data. */
  tainted: Set<string>;
  /** The line each tainted variable was introduced on, for evidence. */
  origin: Map<string, number>;
  /** Direct-source test for this file's language. */
  isDirect(expression: string): boolean;
}

/**
 * Walks a file top to bottom collecting variables that carry user input.
 * Propagation is transitive: once `a` is tainted, `const b = a.trim()` taints
 * `b` too. Fixed-point iteration handles use-before-assignment orderings.
 */
export function buildTaintMap(target: ScanTarget): TaintMap {
  const tainted = new Set<string>();
  const origin = new Map<string, number>();
  const isDirect = directSourceFor(target.language);

  const record = (name: string, line: number): void => {
    if (!name || tainted.has(name)) return;
    tainted.add(name);
    origin.set(name, line);
  };

  // Two passes are enough in practice for straight-line code and cheap enough
  // to be unconditional.
  for (let pass = 0; pass < 2; pass += 1) {
    for (let index = 0; index < target.lines.length; index += 1) {
      const raw = target.lines[index]!;
      const lineNumber = index + 1;

      const destructured = DESTRUCTURE.exec(raw);
      if (destructured && isTaintedExpression(destructured[2]!, tainted, isDirect)) {
        for (const part of destructured[1]!.split(',')) {
          const name = part.split(':').pop()!.replace(/[^A-Za-z0-9_]/g, '').trim();
          record(name, lineNumber);
        }
        continue;
      }

      const assignment = ASSIGNMENT.exec(raw);
      if (!assignment) continue;
      const [, name, initializer] = assignment;
      if (!name || !initializer) continue;
      if (isTaintedExpression(initializer, tainted, isDirect)) record(name, lineNumber);
    }
  }

  return { tainted, origin, isDirect };
}

/** True when the expression reads a request source or an already-tainted variable. */
export function isTaintedExpression(
  expression: string,
  tainted: Set<string>,
  isDirect: (expression: string) => boolean = isDirectUserInput,
): boolean {
  if (isDirect(expression)) return true;
  if (tainted.size === 0) return false;
  for (const name of tainted) {
    // Word-boundary match so `id` does not match `valid`.
    // security-review-ignore-next-line dangerous-api/regex-from-user-input
    // The pattern is built from an identifier read out of the file being analysed,
    // and it goes through escapeRegExp first, so it cannot carry regex syntax.
    if (new RegExp(`(?<![A-Za-z0-9_$])\\$?${escapeRegExp(name)}(?![A-Za-z0-9_$])`).test(expression)) {
      return true;
    }
  }
  return false;
}

/**
 * How strongly we believe the expression is attacker-reachable:
 * `direct` - reads a request object right here;
 * `variable` - reads a variable we traced back to a request object;
 * `naming` - only the identifier name suggests external data;
 * `none` - no signal at all.
 */
export type TaintStrength = 'direct' | 'variable' | 'naming' | 'none';

export function taintStrength(expression: string, map: TaintMap): TaintStrength {
  if (map.isDirect(expression)) return 'direct';
  for (const name of map.tainted) {
    // security-review-ignore-next-line dangerous-api/regex-from-user-input
    // As above: the name comes from the analysed file and is escaped first.
    if (new RegExp(`(?<![A-Za-z0-9_$])\\$?${escapeRegExp(name)}(?![A-Za-z0-9_$])`).test(expression)) {
      return 'variable';
    }
  }
  if (looksLikeUserInputName(expression)) return 'naming';
  return 'none';
}

export function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
