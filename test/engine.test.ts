import { describe, expect, it } from 'vitest';
import { ALL_RULES, rank, scan, worstSeverity } from '../src/analysis/engine';
import type { FileInput } from '../src/analysis/engine';
import type { Finding } from '../src/analysis/types';

function file(filePath: string, content: string, changedLines: Set<number> | null = null): FileInput {
  return { filePath, content: content.replace(/^\n/, ''), status: 'modified', changedLines };
}

describe('engine', () => {
  it('exposes one rule per category', () => {
    expect(ALL_RULES).toHaveLength(6);
    expect(new Set(ALL_RULES.map((rule) => rule.category)).size).toBe(6);
  });

  it('finds issues across several categories in one pass', () => {
    const summary = scan([
      file(
        'src/app.ts',
        `
const key = "AKIAIOSFODNN7EXAMPLE";
app.get('/u/:id', async (req, res) => {
  const rows = await db.query(\`SELECT * FROM users WHERE id = \${req.params.id}\`);
  res.end(eval(req.query.expr));
});
`,
      ),
    ]);
    const categories = new Set(summary.findings.map((finding) => finding.category));
    expect(categories.has('secrets')).toBe(true);
    expect(categories.has('sql-injection')).toBe(true);
    expect(categories.has('dangerous-api')).toBe(true);
    expect(summary.filesScanned).toBe(1);
    expect(summary.countsBySeverity.critical).toBeGreaterThan(0);
  });

  it('only reports on changed lines when a line set is supplied', () => {
    const content = ['const a = 1;', 'const key = "AKIAIOSFODNN7EXAMPLE";'].join('\n');
    expect(scan([file('src/a.ts', content, new Set([1]))]).findings).toEqual([]);
    expect(scan([file('src/a.ts', content, new Set([2]))]).findings.length).toBeGreaterThan(0);
  });

  it('honours an inline suppression on the same line', () => {
    const summary = scan([
      file('src/a.ts', 'const key = "AKIAIOSFODNN7EXAMPLE"; // security-review-ignore secrets'),
    ]);
    expect(summary.findings).toEqual([]);
  });

  it('honours a suppression on the preceding line', () => {
    const summary = scan([
      file(
        'src/a.ts',
        ['// security-review-ignore-next-line secrets/aws-access-key-id', 'const key = "AKIAIOSFODNN7EXAMPLE";'].join(
          '\n',
        ),
      ),
    ]);
    expect(summary.findings).toEqual([]);
  });

  it('does not let a suppression for one rule hide another', () => {
    const summary = scan([
      file('src/a.ts', 'const key = "AKIAIOSFODNN7EXAMPLE"; // security-review-ignore dangerous-api'),
    ]);
    expect(summary.findings.length).toBeGreaterThan(0);
  });

  it('skips test paths by default and scans them on request', () => {
    const input = file('test/fixtures/keys.test.ts', 'const key = "AKIAIOSFODNN7EXAMPLE";');
    expect(scan([input]).filesScanned).toBe(0);
    expect(scan([input], { includeTests: true }).findings.length).toBeGreaterThan(0);
  });

  it('skips generated paths and lockfiles', () => {
    expect(scan([file('node_modules/x/index.js', 'eval(a);')]).filesScanned).toBe(0);
    expect(scan([file('package-lock.json', '{"x": 1}')]).filesScanned).toBe(0);
    expect(scan([file('dist/bundle.min.js', 'eval(a);')]).filesScanned).toBe(0);
  });

  it('skips removed files', () => {
    const summary = scan([
      { filePath: 'src/old.ts', content: 'eval(x);', status: 'removed', changedLines: null },
    ]);
    expect(summary.filesScanned).toBe(0);
  });

  it('applies the minimum severity filter', () => {
    const content = 'const tmp = "/tmp/session.lock";';
    expect(scan([content].map((c) => file('src/a.ts', c)), { minSeverity: 'low' }).findings.length).toBeGreaterThan(0);
    expect(scan([content].map((c) => file('src/a.ts', c)), { minSeverity: 'critical' }).findings).toEqual([]);
  });

  it('honours a disabled category', () => {
    const input = file('src/a.ts', 'const key = "AKIAIOSFODNN7EXAMPLE";');
    expect(scan([input], { disabledRules: ['secrets'] }).findings).toEqual([]);
  });

  it('runs only the requested categories', () => {
    const input = file('src/a.ts', 'const key = "AKIAIOSFODNN7EXAMPLE";');
    expect(scan([input], { categories: ['dangerous-api'] }).findings).toEqual([]);
    expect(scan([input], { categories: ['secrets'] }).findings.length).toBeGreaterThan(0);
  });

  it('caps findings per file', () => {
    const lines = Array.from({ length: 40 }, (_, index) => `eval(payload${index});`);
    const summary = scan([file('src/a.ts', lines.join('\n'))], { maxFindingsPerFile: 5 });
    expect(summary.findings).toHaveLength(5);
  });

  it('deduplicates identical findings', () => {
    const summary = scan([
      file('src/a.ts', ['eval(sameThing);', 'eval(sameThing);'].join('\n')),
    ]);
    expect(summary.findings.filter((f) => f.ruleId === 'dangerous-api/eval')).toHaveLength(1);
  });

  it('keeps going when one rule throws', () => {
    const broken = {
      id: 'broken',
      category: 'secrets' as const,
      description: 'always throws',
      languages: ['*'] as const,
      check() {
        throw new Error('boom');
      },
    };
    ALL_RULES.push(broken);
    try {
      const summary = scan([file('src/a.ts', 'const key = "AKIAIOSFODNN7EXAMPLE";')]);
      expect(summary.findings.length).toBeGreaterThan(0);
    } finally {
      ALL_RULES.pop();
    }
  });

  it('ranks worst and most certain first', () => {
    const base = {
      category: 'secrets' as const,
      title: 't',
      description: 'd',
      remediation: 'r',
      filePath: 'a.ts',
      line: 1,
      snippet: 's',
    };
    const ordered = rank([
      { ...base, ruleId: 'c', severity: 'low', confidence: 'high', fingerprint: '3' },
      { ...base, ruleId: 'a', severity: 'critical', confidence: 'low', fingerprint: '1' },
      { ...base, ruleId: 'b', severity: 'critical', confidence: 'high', fingerprint: '2' },
    ] as Finding[]);
    expect(ordered.map((finding) => finding.ruleId)).toEqual(['b', 'a', 'c']);
    expect(worstSeverity(ordered)).toBe('critical');
    expect(worstSeverity([])).toBeNull();
  });
});

describe('language routing', () => {
  it('does not report code sinks in documentation prose', () => {
    const prose = 'The reviewer flags `eval` and dynamic code evaluation, and `exec` built from input.';
    expect(scan([file('README.md', prose)]).findings).toEqual([]);
    expect(scan([file('docs/guide.rst', prose)]).findings).toEqual([]);
  });

  it('still reports a credential pasted into documentation', () => {
    const findings = scan([file('README.md', 'Set the key to AKIAIOSFODNN7EXAMPLE before running.')]).findings;
    expect(findings.map((f) => f.ruleId)).toContain('secrets/aws-access-key-id');
  });

  it('keeps scanning requirements.txt as a manifest, not as prose', () => {
    const findings = scan([file('requirements.txt', 'pyyaml==5.3.1')]).findings;
    expect(findings.map((f) => f.ruleId)).toContain('dependencies/known-vulnerable-version');
  });

  it('scans constraints.txt too', () => {
    const findings = scan([file('constraints.txt', 'requests==2.30.0')]).findings;
    expect(findings.map((f) => f.ruleId)).toContain('dependencies/known-vulnerable-version');
  });
});

describe('file-level suppression', () => {
  it('waives the named rules for the whole file', () => {
    const content = [
      '// security-review-ignore-file dangerous-api',
      'eval(a);',
      'eval(b);',
    ].join('\n');
    expect(scan([file('src/patterns.ts', content)]).findings).toEqual([]);
  });

  it('does not waive rules it did not name', () => {
    const content = [
      '// security-review-ignore-file dangerous-api',
      'const key = "AKIAIOSFODNN7EXAMPLE";',
    ].join('\n');
    expect(scan([file('src/patterns.ts', content)]).findings.length).toBeGreaterThan(0);
  });

  it('ignores an unqualified directive, which would be too blunt', () => {
    const content = ['// security-review-ignore-file', 'eval(a);'].join('\n');
    expect(scan([file('src/patterns.ts', content)]).findings.length).toBeGreaterThan(0);
  });

  it('only honours the directive in a file header', () => {
    const buried = [
      ...Array.from({ length: 40 }, () => '// filler'),
      '// security-review-ignore-file dangerous-api',
      'eval(a);',
    ].join('\n');
    expect(scan([file('src/patterns.ts', buried)]).findings.length).toBeGreaterThan(0);
  });

  it('finds a line directive above an explanatory comment block', () => {
    const content = [
      '// security-review-ignore-next-line dangerous-api/eval',
      '// The expression is a compile-time constant, checked by the caller.',
      'eval(TRUSTED_CONSTANT);',
    ].join('\n');
    expect(scan([file('src/calc.ts', content)]).findings).toEqual([]);
  });
});
