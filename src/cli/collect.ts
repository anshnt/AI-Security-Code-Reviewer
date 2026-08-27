import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync, statSync, type Dirent, type Stats } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { parsePatch } from '../analysis/diff';
import type { FileInput } from '../analysis/engine';
import { isGeneratedPath } from '../analysis/source';
import { pathInScope, type RepoConfig } from '../config/repo-config';

/**
 * Gathering files for a local scan.
 *
 * Two modes, because they answer different questions. Scanning the working tree
 * answers "what is wrong with this code?"; scanning a diff answers "what did I
 * just add?" - which is the same question the pull-request reviewer asks, and
 * the one worth asking before pushing.
 *
 * The diff mode reuses the same patch parser the reviewer uses, so a finding
 * reported locally and a finding reported on the pull request come from
 * identical inputs. A local check that disagrees with CI is worse than no local
 * check.
 */

/** Directories never worth walking into. */
const SKIP_DIRECTORIES = new Set([
  '.git',
  'node_modules',
  'dist',
  'build',
  'out',
  'coverage',
  'vendor',
  '.next',
  '.nuxt',
  '.svelte-kit',
  '.venv',
  'venv',
  '__pycache__',
  '.mypy_cache',
  '.pytest_cache',
  '.gradle',
  'target',
  '.terraform',
  '.idea',
  '.vscode',
]);

/** Extensions the analyzers can say something about. */
const SCANNABLE = new Set([
  'js', 'jsx', 'mjs', 'cjs', 'ts', 'tsx', 'mts', 'cts',
  'py', 'pyi', 'java', 'kt', 'go', 'rb', 'erb', 'php', 'cs',
  'sql', 'yml', 'yaml', 'json', 'tf', 'tfvars', 'sh', 'bash', 'zsh',
  'env', 'properties', 'xml', 'gradle', 'pem', 'txt', 'toml',
]);

/** Files worth reading even without a matching extension. */
const SCANNABLE_NAMES = new Set([
  'Dockerfile',
  'Gemfile',
  'Pipfile',
  'go.mod',
  'pom.xml',
  '.env',
  '.npmrc',
  '.netrc',
]);

export interface CollectOptions {
  /** Skip files larger than this, in bytes. */
  maxFileBytes: number;
  repoConfig: RepoConfig;
}

export interface CollectResult {
  files: FileInput[];
  /** Paths that were found but could not be read, with the reason. */
  skipped: { path: string; reason: string }[];
}

export function collectFromPaths(
  roots: readonly string[],
  options: CollectOptions,
): CollectResult {
  const files: FileInput[] = [];
  const skipped: { path: string; reason: string }[] = [];
  const seen = new Set<string>();

  const consider = (absolutePath: string): void => {
    const relativePath = displayPath(absolutePath);
    if (seen.has(relativePath)) return;
    seen.add(relativePath);

    if (isGeneratedPath(relativePath)) return;
    if (!pathInScope(options.repoConfig, relativePath)) return;
    if (!isScannable(relativePath)) return;

    let stats: Stats;
    try {
      stats = statSync(absolutePath);
    } catch (error) {
      skipped.push({ path: relativePath, reason: (error as Error).message });
      return;
    }
    if (stats.size > options.maxFileBytes) {
      skipped.push({ path: relativePath, reason: `larger than ${options.maxFileBytes} bytes` });
      return;
    }

    let content: string;
    try {
      const buffer = readFileSync(absolutePath);
      if (buffer.subarray(0, 1024).includes(0)) return; // binary
      content = buffer.toString('utf8');
    } catch (error) {
      skipped.push({ path: relativePath, reason: (error as Error).message });
      return;
    }

    files.push({ filePath: relativePath, content, status: 'modified', changedLines: null });
  };

  const walk = (directory: string): void => {
    let entries: Dirent[];
    try {
      entries = readdirSync(directory, { withFileTypes: true });
    } catch (error) {
      skipped.push({ path: toPosix(relative(process.cwd(), directory)), reason: (error as Error).message });
      return;
    }
    for (const entry of entries) {
      const full = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRECTORIES.has(entry.name)) continue;
        walk(full);
      } else if (entry.isFile()) {
        consider(full);
      }
      // Symlinks are deliberately not followed: a link out of the tree is not
      // this repository's code, and a link cycle would not terminate.
    }
  };

  for (const root of roots) {
    let stats: Stats;
    try {
      stats = statSync(root);
    } catch (error) {
      skipped.push({ path: root, reason: (error as Error).message });
      continue;
    }
    if (stats.isDirectory()) walk(root);
    else consider(root);
  }

  return { files, skipped };
}

export interface DiffResult extends CollectResult {
  /** Absent when git could not be used; the caller reports it. */
  error?: string;
}

/**
 * Files and changed lines from `git diff`.
 *
 * `spawnSync` with an argument array and no shell, deliberately. Building a
 * command string here and handing it to a shell is the exact pattern this tool's
 * own `dangerous-api/shell-exec` rule flags - a branch name is attacker-supplied
 * data in any repository that accepts pull requests.
 */
export function collectFromDiff(ref: string, options: CollectOptions): DiffResult {
  const files: FileInput[] = [];
  const skipped: { path: string; reason: string }[] = [];

  const diff = spawnSync(
    'git',
    ['diff', '--no-color', '--unified=3', '--diff-filter=d', ref, '--'],
    { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
  );

  if (diff.error) {
    return { files, skipped, error: `could not run git: ${diff.error.message}` };
  }
  if (diff.status !== 0) {
    const message = (diff.stderr || '').trim() || `git exited with status ${String(diff.status)}`;
    return { files, skipped, error: message };
  }

  for (const [path, patch] of splitMultiFileDiff(diff.stdout)) {
    if (isGeneratedPath(path)) continue;
    if (!pathInScope(options.repoConfig, path)) continue;
    if (!isScannable(path)) continue;

    const parsed = parsePatch(patch);
    if (parsed.changedLines.size === 0) continue;

    // Read the post-change content from disk so rules see the same surrounding
    // context they would on a pull request.
    let content: string;
    try {
      const buffer = readFileSync(path);
      if (buffer.subarray(0, 1024).includes(0)) continue;
      content = buffer.toString('utf8');
    } catch (error) {
      skipped.push({ path, reason: (error as Error).message });
      continue;
    }

    files.push({
      filePath: path,
      content,
      status: 'modified',
      changedLines: parsed.changedLines,
    });
  }

  return { files, skipped };
}

/**
 * Splits a multi-file `git diff` into per-file patches.
 *
 * The `+++ b/<path>` line is the source of truth for the path rather than the
 * `diff --git` header, because a path containing a space is unambiguous there
 * and ambiguous in the header.
 */
export function splitMultiFileDiff(diff: string): Map<string, string> {
  const out = new Map<string, string>();
  let currentPath: string | null = null;
  let buffer: string[] = [];

  const flush = (): void => {
    if (currentPath && buffer.length > 0) out.set(currentPath, buffer.join('\n'));
    buffer = [];
  };

  for (const line of diff.split('\n')) {
    if (line.startsWith('diff --git ')) {
      flush();
      currentPath = null;
      continue;
    }
    if (line.startsWith('+++ ')) {
      const target = line.slice(4).trim();
      currentPath = target === '/dev/null' ? null : target.replace(/^b\//, '');
      continue;
    }
    if (line.startsWith('--- ') || line.startsWith('index ') || line.startsWith('old mode ') ||
        line.startsWith('new mode ') || line.startsWith('similarity index ') ||
        line.startsWith('rename ') || line.startsWith('new file mode ') ||
        line.startsWith('deleted file mode ') || line.startsWith('Binary files ')) {
      continue;
    }
    if (currentPath && (line.startsWith('@@') || line.startsWith('+') || line.startsWith('-') ||
        line.startsWith(' ') || line.startsWith('\\'))) {
      buffer.push(line);
    }
  }
  flush();
  return out;
}

function isScannable(filePath: string): boolean {
  const base = filePath.split('/').pop() ?? filePath;
  if (SCANNABLE_NAMES.has(base)) return true;
  if (base.startsWith('.env')) return true;
  if (base.startsWith('requirements') && base.endsWith('.txt')) return true;
  const ext = base.includes('.') ? base.split('.').pop()!.toLowerCase() : '';
  return SCANNABLE.has(ext);
}

function toPosix(value: string): string {
  return sep === '/' ? value : value.split(sep).join('/');
}

/**
 * How a path is shown, and keyed, in the report.
 *
 * Relative to the working directory when the file is inside it, which is the
 * normal case and the form an editor can jump to. A path outside the working
 * directory would relativise to a chain of `../` that is longer and harder to
 * read than the absolute path, so that keeps its absolute form.
 */
function displayPath(absolutePath: string): string {
  const relativePath = relative(process.cwd(), absolutePath);
  if (!relativePath || relativePath.startsWith('..')) return toPosix(absolutePath);
  return toPosix(relativePath);
}
