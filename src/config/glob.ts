/**
 * Path matching for the repository config's include and exclude lists.
 *
 * A dependency-free subset of glob syntax, because the alternative is pulling in
 * a matcher whose full feature set nobody configuring this file will use, and
 * whose surprises they would have to learn anyway. Supported:
 *
 *   `*`      any run of characters except `/`
 *   `**`     any run of characters including `/`
 *   `?`      exactly one character except `/`
 *   `{a,b}`  either alternative
 *
 * Everything else is literal. A pattern with no slash matches by basename as
 * well as by path, so `*.min.js` behaves the way people expect rather than only
 * matching files at the repository root.
 */

export interface CompiledGlob {
  source: string;
  test(filePath: string): boolean;
}

export function compileGlob(pattern: string): CompiledGlob {
  const trimmed = pattern.trim().replace(/^\.\//, '');
  const anchored = trimmed.includes('/');
  const regex = new RegExp(`^${globToRegExpSource(trimmed)}$`);

  return {
    source: pattern,
    test(filePath: string): boolean {
      const normalized = filePath.replace(/^\.\//, '');
      if (regex.test(normalized)) return true;
      if (!anchored) {
        const base = normalized.split('/').pop() ?? normalized;
        return regex.test(base);
      }
      return false;
    },
  };
}

function globToRegExpSource(pattern: string): string {
  let out = '';
  for (let index = 0; index < pattern.length; index += 1) {
    const char = pattern[index]!;

    if (char === '*') {
      const isDouble = pattern[index + 1] === '*';
      if (isDouble) {
        // `a/**/b` should also match `a/b`, so consume the trailing slash and
        // make the whole segment optional.
        if (pattern[index + 2] === '/') {
          out += '(?:.*/)?';
          index += 2;
        } else {
          out += '.*';
          index += 1;
        }
      } else {
        out += '[^/]*';
      }
      continue;
    }

    if (char === '?') {
      out += '[^/]';
      continue;
    }

    if (char === '{') {
      const close = pattern.indexOf('}', index);
      if (close > index) {
        const alternatives = pattern
          .slice(index + 1, close)
          .split(',')
          .map((entry) => globToRegExpSource(entry));
        out += `(?:${alternatives.join('|')})`;
        index = close;
        continue;
      }
    }

    out += escapeRegExp(char);
  }
  return out;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Compiles a list once, skipping empty entries. */
export function compileGlobs(patterns: readonly string[]): CompiledGlob[] {
  return patterns.map((pattern) => pattern.trim()).filter(Boolean).map(compileGlob);
}

export function matchesAny(globs: readonly CompiledGlob[], filePath: string): boolean {
  return globs.some((glob) => glob.test(filePath));
}
