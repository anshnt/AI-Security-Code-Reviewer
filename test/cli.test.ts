import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { HELP_TEXT, parseArgs } from '../src/cli/args';
import { collectFromPaths, splitMultiFileDiff } from '../src/cli/collect';
import { countBlocking, renderJson, renderPretty, renderRules, shouldUseColor } from '../src/cli/report';
import { emptyRepoConfig } from '../src/config/repo-config';
import { scan } from '../src/analysis/engine';

const VULNERABLE = [
  'import { db } from "./db";',
  '',
  'export async function getInvoice(req, res) {',
  '  const id = req.params.id;',
  '  const rows = await db.query(`SELECT * FROM invoices WHERE id = ${id}`);',
  '  res.json(rows);',
  '}',
].join('\n');

/**
 * Genuinely clean, which takes more than parameterising the query: an earlier
 * draft of this fixture bound its parameters correctly and still tripped
 * `authorization/missing-ownership-check`, because reading an invoice by a
 * client-supplied id with no owner predicate is a real finding. The analyzer was
 * right and the fixture was wrong.
 */
const SAFE = [
  'import { db } from "./db";',
  '',
  'export async function getInvoice(req, res) {',
  '  const rows = await db.query(',
  '    "SELECT * FROM invoices WHERE id = ? AND user_id = ?",',
  '    [req.params.id, req.user.id],',
  '  );',
  '  res.json(rows);',
  '}',
].join('\n');

describe('parseArgs', () => {
  it('defaults to scanning the working directory', () => {
    const { options } = parseArgs([]);
    expect(options).toMatchObject({ command: 'scan', paths: ['.'], failOn: 'high', format: 'pretty' });
  });

  it('accepts an explicit scan command with paths', () => {
    expect(parseArgs(['scan', 'src', 'lib']).options!.paths).toEqual(['src', 'lib']);
  });

  it('treats a bare path as a path, not a command', () => {
    expect(parseArgs(['src']).options!.paths).toEqual(['src']);
  });

  it('reads flag values in both forms', () => {
    expect(parseArgs(['--fail-on', 'critical']).options!.failOn).toBe('critical');
    expect(parseArgs(['--fail-on=critical']).options!.failOn).toBe('critical');
  });

  it('lets --diff default its ref', () => {
    expect(parseArgs(['--diff']).options!.diffAgainst).toBe('HEAD');
    expect(parseArgs(['--diff', 'origin/main']).options!.diffAgainst).toBe('origin/main');
  });

  it('does not swallow a following flag as a value', () => {
    const { options } = parseArgs(['--diff', '--quiet']);
    expect(options).toMatchObject({ diffAgainst: 'HEAD', quiet: true });
  });

  it('splits a comma-separated --disable list', () => {
    expect(parseArgs(['--disable', 'secrets, dependencies']).options!.disabledRules).toEqual([
      'secrets',
      'dependencies',
    ]);
  });

  it('accumulates repeated --disable flags', () => {
    expect(parseArgs(['--disable', 'secrets', '--disable', 'dependencies']).options!.disabledRules).toEqual([
      'secrets',
      'dependencies',
    ]);
  });

  it('treats everything after -- as a path', () => {
    expect(parseArgs(['--', '--weird-filename']).options!.paths).toEqual(['--weird-filename']);
  });

  it('rejects an unknown flag rather than ignoring it', () => {
    // A mistyped --fail-on that is silently dropped turns a gate into a no-op.
    expect(parseArgs(['--fail-onn', 'high']).error).toContain('unknown option');
  });

  it('rejects an invalid severity', () => {
    expect(parseArgs(['--fail-on', 'catastrophic']).error).toContain('--fail-on must be');
    expect(parseArgs(['--min-severity', 'nope']).error).toContain('--min-severity must be');
  });

  it('rejects an invalid format', () => {
    expect(parseArgs(['--format', 'xml']).error).toContain('--format must be');
  });

  it('rejects a --limit that is not a positive number', () => {
    expect(parseArgs(['--limit', '0']).error).toContain('positive');
    expect(parseArgs(['--limit', 'lots']).error).toContain('positive');
  });

  it('requires a value for --config and --disable', () => {
    expect(parseArgs(['--config']).error).toContain('needs a path');
    expect(parseArgs(['--disable']).error).toContain('needs a rule id');
  });

  it('recognises help and version', () => {
    expect(parseArgs(['--help']).options!.command).toBe('help');
    expect(parseArgs(['-h']).options!.command).toBe('help');
    expect(parseArgs(['--version']).options!.command).toBe('version');
    expect(parseArgs(['--list-rules']).options!.command).toBe('rules');
  });

  it('documents every flag it accepts', () => {
    // A flag that works but is not in --help does not exist as far as users go.
    const flags = [
      '--diff',
      '--include-tests',
      '--disable',
      '--min-severity',
      '--format',
      '--limit',
      '--color',
      '--no-color',
      '--quiet',
      '--fail-on',
      '--config',
      '--no-config',
    ];
    for (const flag of flags) expect(HELP_TEXT).toContain(flag);
  });
});

describe('splitMultiFileDiff', () => {
  it('separates per-file patches', () => {
    const diff = [
      'diff --git a/src/a.ts b/src/a.ts',
      'index 111..222 100644',
      '--- a/src/a.ts',
      '+++ b/src/a.ts',
      '@@ -1,1 +1,2 @@',
      ' const a = 1;',
      '+const b = 2;',
      'diff --git a/src/c.ts b/src/c.ts',
      'index 333..444 100644',
      '--- a/src/c.ts',
      '+++ b/src/c.ts',
      '@@ -5,1 +5,1 @@',
      '-old',
      '+new',
    ].join('\n');
    const split = splitMultiFileDiff(diff);
    expect([...split.keys()]).toEqual(['src/a.ts', 'src/c.ts']);
    expect(split.get('src/a.ts')).toContain('+const b = 2;');
    expect(split.get('src/c.ts')).toContain('+new');
  });

  it('skips a deleted file', () => {
    const diff = [
      'diff --git a/gone.ts b/gone.ts',
      'deleted file mode 100644',
      '--- a/gone.ts',
      '+++ /dev/null',
      '@@ -1,1 +0,0 @@',
      '-const a = 1;',
    ].join('\n');
    expect(splitMultiFileDiff(diff).size).toBe(0);
  });

  it('skips a binary file', () => {
    const diff = [
      'diff --git a/logo.png b/logo.png',
      'index 111..222 100644',
      'Binary files a/logo.png and b/logo.png differ',
    ].join('\n');
    expect(splitMultiFileDiff(diff).size).toBe(0);
  });

  it('handles a path containing a space', () => {
    const diff = [
      'diff --git a/my dir/a.ts b/my dir/a.ts',
      '--- a/my dir/a.ts',
      '+++ b/my dir/a.ts',
      '@@ -1,0 +1,1 @@',
      '+const a = 1;',
    ].join('\n');
    expect([...splitMultiFileDiff(diff).keys()]).toEqual(['my dir/a.ts']);
  });

  it('returns nothing for an empty diff', () => {
    expect(splitMultiFileDiff('').size).toBe(0);
  });
});

describe('collectFromPaths', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'review-cli-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  const options = () => ({ maxFileBytes: 400_000, repoConfig: emptyRepoConfig() });

  it('walks a directory and reads scannable files', () => {
    writeFileSync(join(dir, 'a.ts'), VULNERABLE);
    writeFileSync(join(dir, 'b.py'), 'x = 1\n');
    const result = collectFromPaths([dir], options());
    expect(result.files).toHaveLength(2);
  });

  it('ignores files with no analyzer for them', () => {
    writeFileSync(join(dir, 'notes.rtf'), 'hello');
    writeFileSync(join(dir, 'a.ts'), 'const a = 1;');
    expect(collectFromPaths([dir], options()).files.map((f) => f.filePath.split('/').pop())).toEqual([
      'a.ts',
    ]);
  });

  it('does not descend into dependency and build directories', () => {
    mkdirSync(join(dir, 'node_modules'));
    writeFileSync(join(dir, 'node_modules', 'dep.js'), 'eval(x);');
    mkdirSync(join(dir, 'dist'));
    writeFileSync(join(dir, 'dist', 'out.js'), 'eval(x);');
    writeFileSync(join(dir, 'a.ts'), 'const a = 1;');
    expect(collectFromPaths([dir], options()).files).toHaveLength(1);
  });

  it('skips a file over the size limit and says so', () => {
    writeFileSync(join(dir, 'big.ts'), 'x'.repeat(2000));
    const result = collectFromPaths([dir], { maxFileBytes: 100, repoConfig: emptyRepoConfig() });
    expect(result.files).toHaveLength(0);
    expect(result.skipped[0]!.reason).toContain('larger than');
  });

  it('skips binary content', () => {
    writeFileSync(join(dir, 'blob.json'), Buffer.from([0x7b, 0x00, 0x01, 0x7d]));
    expect(collectFromPaths([dir], options()).files).toHaveLength(0);
  });

  it('reports a path that does not exist rather than failing', () => {
    const result = collectFromPaths([join(dir, 'missing')], options());
    expect(result.files).toHaveLength(0);
    expect(result.skipped).toHaveLength(1);
  });

  it('accepts a single file path', () => {
    const file = join(dir, 'a.ts');
    writeFileSync(file, VULNERABLE);
    expect(collectFromPaths([file], options()).files).toHaveLength(1);
  });

  it('does not read the same file twice when a path is repeated', () => {
    const file = join(dir, 'a.ts');
    writeFileSync(file, VULNERABLE);
    expect(collectFromPaths([file, file, dir], options()).files).toHaveLength(1);
  });

  it('honours a config exclusion', () => {
    writeFileSync(join(dir, 'a.ts'), VULNERABLE);
    mkdirSync(join(dir, 'vendor'));
    writeFileSync(join(dir, 'vendor', 'lib.ts'), VULNERABLE);
    const repoConfig = emptyRepoConfig();
    repoConfig.excludeGlobs = [{ source: 'vendor/**', test: (p: string) => p.includes('vendor/') }];
    const result = collectFromPaths([dir], { maxFileBytes: 400_000, repoConfig });
    expect(result.files).toHaveLength(1);
  });
});

describe('report rendering', () => {
  const summary = () =>
    scan([{ filePath: 'src/a.ts', content: VULNERABLE, status: 'modified', changedLines: null }]);

  const reportOptions = (overrides = {}) => ({
    color: false,
    limit: 50,
    quiet: false,
    failOn: 'high' as const,
    skipped: [],
    configWarnings: [],
    scope: 'working tree',
    ...overrides,
  });

  it('leads with severity, location and a fix', () => {
    const text = renderPretty(summary(), reportOptions());
    expect(text).toContain('CRITICAL');
    expect(text).toContain('src/a.ts:5');
    expect(text).toContain('Fix:');
    expect(text).toContain('sql-injection/interpolated-query');
  });

  it('says plainly when there is nothing to report', () => {
    const clean = scan([{ filePath: 'src/a.ts', content: SAFE, status: 'modified', changedLines: null }]);
    expect(renderPretty(clean, reportOptions())).toContain('No findings');
  });

  it('uses singular wording for one finding', () => {
    const one = scan([
      { filePath: 'src/a.ts', content: 'eval(userInput);', status: 'modified', changedLines: null },
    ]);
    const text = renderPretty(one, reportOptions({ quiet: true }));
    expect(text).toContain('1 finding in 1 file');
    expect(text).not.toContain('1 findings');
  });

  it('prints only the summary in quiet mode', () => {
    const text = renderPretty(summary(), reportOptions({ quiet: true }));
    expect(text).not.toContain('Fix:');
    expect(text).toContain('in 1 file');
  });

  it('says how many findings the limit hid', () => {
    const many = scan([
      {
        filePath: 'src/a.ts',
        content: Array.from({ length: 6 }, (_, i) => `eval(payload${i});`).join('\n'),
        status: 'modified',
        changedLines: null,
      },
    ]);
    expect(renderPretty(many, reportOptions({ limit: 2 }))).toContain('further');
  });

  it('reports unreadable paths rather than hiding them', () => {
    const text = renderPretty(
      summary(),
      reportOptions({ skipped: [{ path: 'src/b.ts', reason: 'permission denied' }] }),
    );
    expect(text).toContain('could not be read');
    expect(text).toContain('permission denied');
  });

  it('shows config warnings first', () => {
    const text = renderPretty(summary(), reportOptions({ configWarnings: ['bad key "foo"'] }));
    expect(text.indexOf('bad key "foo"')).toBeLessThan(text.indexOf('CRITICAL'));
  });

  it('says it is not gating when --fail-on is never', () => {
    expect(renderPretty(summary(), reportOptions({ failOn: 'never', quiet: true }))).toContain(
      'not gating',
    );
  });

  it('emits no escape codes when colour is off', () => {
    expect(renderPretty(summary(), reportOptions())).not.toMatch(/\[/);
  });

  it('emits escape codes when colour is on', () => {
    expect(renderPretty(summary(), reportOptions({ color: true }))).toMatch(/\[/);
  });

  it('produces JSON that is stable enough to script against', () => {
    const parsed = JSON.parse(renderJson(summary(), reportOptions())) as {
      summary: { findingsCount: number; blocking: number; failOn: string };
      findings: { ruleId: string }[];
    };
    expect(parsed.summary.findingsCount).toBeGreaterThan(0);
    expect(parsed.summary.blocking).toBeGreaterThan(0);
    expect(parsed.summary.failOn).toBe('high');
    expect(parsed.findings[0]!.ruleId).toBe('sql-injection/interpolated-query');
  });

  it('lists every analyzer with its description', () => {
    const text = renderRules(false);
    for (const id of ['sql-injection', 'authentication', 'secrets', 'dependencies', 'authorization', 'dangerous-api']) {
      expect(text).toContain(id);
    }
  });

  it('counts blocking findings against the threshold', () => {
    const findings = summary().findings;
    expect(countBlocking(findings, 'critical')).toBeGreaterThan(0);
    expect(countBlocking(findings, 'never')).toBe(0);
  });
});

describe('colour detection', () => {
  const original = { ...process.env };

  afterEach(() => {
    process.env = { ...original };
  });

  it('honours an explicit override either way', () => {
    process.env.NO_COLOR = '1';
    expect(shouldUseColor(true)).toBe(true);
    delete process.env.NO_COLOR;
    expect(shouldUseColor(false)).toBe(false);
  });

  it('honours NO_COLOR', () => {
    process.env.NO_COLOR = '1';
    expect(shouldUseColor(null)).toBe(false);
  });

  it('honours FORCE_COLOR', () => {
    delete process.env.NO_COLOR;
    process.env.FORCE_COLOR = '1';
    expect(shouldUseColor(null)).toBe(true);
  });
});

/**
 * The exit-status contract, exercised as a real process. A pre-commit hook or a
 * pipeline step depends on 0/1/2 meaning exactly what the help text says, so
 * these run the built entry point rather than calling `run()` in-process.
 */
describe('exit status', () => {
  let dir: string;
  const cli = resolve('src/cli/index.ts');

  function invoke(args: string[], cwd = dir): { status: number; stdout: string; stderr: string } {
    const result = spawnSync('npx', ['tsx', cli, ...args], {
      cwd,
      encoding: 'utf8',
      env: { ...process.env, NO_COLOR: '1' },
    });
    return { status: result.status ?? -1, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
  }

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'review-cli-exit-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('exits 0 on a clean tree', () => {
    writeFileSync(join(dir, 'a.ts'), SAFE);
    const result = invoke(['.']);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('No findings');
  });

  it('exits 1 when a finding meets the threshold', () => {
    writeFileSync(join(dir, 'a.ts'), VULNERABLE);
    const result = invoke(['.']);
    expect(result.status).toBe(1);
    expect(result.stdout).toContain('SQL query built by string interpolation');
  });

  it('exits 0 when the threshold is above every finding', () => {
    writeFileSync(join(dir, 'a.ts'), 'const tmp = "/tmp/session.lock";');
    const result = invoke(['.', '--fail-on', 'critical']);
    expect(result.status).toBe(0);
  });

  it('exits 0 with --fail-on never even with critical findings', () => {
    writeFileSync(join(dir, 'a.ts'), VULNERABLE);
    expect(invoke(['.', '--fail-on', 'never']).status).toBe(0);
  });

  it('exits 2 for an unknown flag, distinguishing "could not look" from "found problems"', () => {
    const result = invoke(['--nonsense']);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('unknown option');
  });

  it('exits 2 when a named config file is missing', () => {
    const result = invoke(['.', '--config', 'nope.yml']);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('no such config file');
  });

  it('exits 0 for --help and --list-rules', () => {
    expect(invoke(['--help']).status).toBe(0);
    expect(invoke(['--list-rules']).status).toBe(0);
  });

  it('reads a config file it finds automatically', () => {
    writeFileSync(join(dir, 'a.ts'), VULNERABLE);
    writeFileSync(join(dir, '.securityreview.yml'), 'rules:\n  disable: [sql-injection]\n');
    const result = invoke(['.']);
    expect(result.stdout).not.toContain('SQL query built by string interpolation');
  });

  it('ignores that config file with --no-config', () => {
    writeFileSync(join(dir, 'a.ts'), VULNERABLE);
    writeFileSync(join(dir, '.securityreview.yml'), 'rules:\n  disable: [sql-injection]\n');
    const result = invoke(['.', '--no-config']);
    expect(result.stdout).toContain('SQL query built by string interpolation');
  });

  it('surfaces config warnings without failing', () => {
    writeFileSync(join(dir, 'a.ts'), SAFE);
    writeFileSync(join(dir, '.securityreview.yml'), 'rulez:\n  disable: [secrets]\n');
    const result = invoke(['.']);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('unknown setting');
  });
});

/**
 * Diff mode against a real git repository, since the whole point is that it
 * agrees with what the pull-request reviewer would report.
 */
describe('diff mode', () => {
  let dir: string;
  const cli = resolve('src/cli/index.ts');

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'review-cli-git-'));
    const git = (...args: string[]): void => {
      execFileSync('git', args, { cwd: dir, stdio: 'ignore' });
    };
    git('init', '-q');
    git('config', 'user.email', 'test@example.com');
    git('config', 'user.name', 'test');
    mkdirSync(join(dir, 'src'));
    writeFileSync(join(dir, 'src', 'a.ts'), SAFE);
    git('add', '-A');
    git('commit', '-q', '-m', 'base');
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function invoke(args: string[]): { status: number; stdout: string; stderr: string } {
    const result = spawnSync('npx', ['tsx', cli, ...args], {
      cwd: dir,
      encoding: 'utf8',
      env: { ...process.env, NO_COLOR: '1' },
    });
    return { status: result.status ?? -1, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
  }

  it('reports nothing when the diff is empty', () => {
    const result = invoke(['--diff', 'HEAD']);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('No findings');
  });

  it('reports a finding on a newly changed line', () => {
    writeFileSync(join(dir, 'src', 'a.ts'), `${SAFE}\n\nexport function bad(req) {\n  return db.query(\`SELECT * FROM t WHERE n = '\${req.query.n}'\`);\n}\n`);
    const result = invoke(['--diff', 'HEAD']);
    expect(result.status).toBe(1);
    expect(result.stdout).toContain('changed lines against HEAD');
    expect(result.stdout).toContain('SQL query built by string interpolation');
  });

  it('does not report a pre-existing problem on an untouched line', () => {
    // Commit a vulnerability, then change something else entirely.
    writeFileSync(join(dir, 'src', 'a.ts'), `${SAFE}\n\nexport function bad(req) {\n  return db.query(\`SELECT * FROM t WHERE n = '\${req.query.n}'\`);\n}\n`);
    execFileSync('git', ['add', '-A'], { cwd: dir, stdio: 'ignore' });
    execFileSync('git', ['commit', '-q', '-m', 'add problem'], { cwd: dir, stdio: 'ignore' });
    writeFileSync(join(dir, 'src', 'unrelated.ts'), 'export const version = 2;\n');

    const result = invoke(['--diff', 'HEAD']);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('No findings');
  });

  it('exits 2 for a ref that does not exist', () => {
    const result = invoke(['--diff', 'no-such-ref']);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('security-review:');
  });
});
