import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { compileGlob, matchesAny, compileGlobs } from '../src/config/glob';
import { mergeRepoConfig } from '../src/config/merge';
import { emptyRepoConfig, parseRepoConfig, pathInScope } from '../src/config/repo-config';
import { loadConfig, type AppConfig } from '../src/config';

function baseConfig(overrides: Partial<AppConfig['review']> = {}): AppConfig {
  const base = loadConfig();
  return {
    ...base,
    github: { ...base.github, token: 't', webhookSecret: 's' },
    storage: { databasePath: ':memory:' },
    review: { ...base.review, failOnSeverity: 'high', ...overrides },
  };
}

describe('compileGlob', () => {
  it('matches a single segment with *', () => {
    const glob = compileGlob('src/*.ts');
    expect(glob.test('src/app.ts')).toBe(true);
    expect(glob.test('src/nested/app.ts')).toBe(false);
  });

  it('crosses directories with **', () => {
    const glob = compileGlob('src/**/*.ts');
    expect(glob.test('src/app.ts')).toBe(true);
    expect(glob.test('src/a/b/c/app.ts')).toBe(true);
    expect(glob.test('lib/app.ts')).toBe(false);
  });

  it('matches a whole subtree', () => {
    const glob = compileGlob('vendor/**');
    expect(glob.test('vendor/lib/thing.js')).toBe(true);
    expect(glob.test('vendors/lib.js')).toBe(false);
  });

  it('matches by basename when the pattern has no slash', () => {
    const glob = compileGlob('*.min.js');
    expect(glob.test('bundle.min.js')).toBe(true);
    expect(glob.test('static/js/bundle.min.js')).toBe(true);
    expect(glob.test('bundle.js')).toBe(false);
  });

  it('handles ? and alternatives', () => {
    expect(compileGlob('a?c.ts').test('abc.ts')).toBe(true);
    expect(compileGlob('a?c.ts').test('ac.ts')).toBe(false);
    const alt = compileGlob('src/*.{spec,test}.ts');
    expect(alt.test('src/a.spec.ts')).toBe(true);
    expect(alt.test('src/a.test.ts')).toBe(true);
    expect(alt.test('src/a.impl.ts')).toBe(false);
  });

  it('treats regex metacharacters as literals', () => {
    const glob = compileGlob('src/a+b(1).ts');
    expect(glob.test('src/a+b(1).ts')).toBe(true);
    expect(glob.test('src/aab1.ts')).toBe(false);
  });

  it('ignores a leading ./ on both sides', () => {
    expect(compileGlob('./src/*.ts').test('src/a.ts')).toBe(true);
    expect(compileGlob('src/*.ts').test('./src/a.ts')).toBe(true);
  });

  it('drops empty patterns from a list', () => {
    expect(compileGlobs(['', '  ', 'src/*.ts'])).toHaveLength(1);
  });

  it('matchesAny is a disjunction', () => {
    const globs = compileGlobs(['vendor/**', '*.min.js']);
    expect(matchesAny(globs, 'vendor/x.js')).toBe(true);
    expect(matchesAny(globs, 'a/b.min.js')).toBe(true);
    expect(matchesAny(globs, 'src/app.ts')).toBe(false);
  });
});

describe('parseRepoConfig', () => {
  it('reads a complete file', () => {
    const config = parseRepoConfig(
      `
version: 1
paths:
  exclude:
    - vendor/**
    - "*.min.js"
  include-tests: true
rules:
  disable:
    - dangerous-api/insecure-temp-file
    - dependencies
severity:
  min: medium
  fail-on: critical
  overrides:
    dangerous-api/weak-cipher: low
inline:
  enabled: false
  max-comments: 5
  min-severity: high
triage:
  enabled: false
  min-severity: critical
`,
      '.securityreview.yml',
    );

    expect(config.present).toBe(true);
    expect(config.warnings).toEqual([]);
    expect(config.excludeGlobs).toHaveLength(2);
    expect(config.includeTests).toBe(true);
    expect(config.disabledRules).toEqual(['dangerous-api/insecure-temp-file', 'dependencies']);
    expect(config.minSeverity).toBe('medium');
    expect(config.failOnSeverity).toBe('critical');
    expect(config.severityOverrides.get('dangerous-api/weak-cipher')).toBe('low');
    expect(config.inline).toEqual({ enabled: false, maxComments: 5, minSeverity: 'high' });
    expect(config.triage).toEqual({ enabled: false, minSeverity: 'critical' });
  });

  it('accepts an empty file as a deliberate no-op', () => {
    const config = parseRepoConfig('', '.securityreview.yml');
    expect(config.present).toBe(true);
    expect(config.warnings).toEqual([]);
  });

  it('accepts a comment-only file', () => {
    const config = parseRepoConfig('# nothing configured yet\n', '.securityreview.yml');
    expect(config.warnings).toEqual([]);
  });

  it('reports invalid YAML rather than throwing', () => {
    const config = parseRepoConfig('paths:\n  exclude: [unclosed\n', '.securityreview.yml');
    expect(config.present).toBe(false);
    expect(config.warnings[0]).toContain('not valid YAML');
  });

  it('rejects a top-level list', () => {
    const config = parseRepoConfig('- a\n- b\n', '.securityreview.yml');
    expect(config.present).toBe(false);
    expect(config.warnings[0]).toContain('mapping at the top level');
  });

  it('warns about an unknown top-level key and names the valid ones', () => {
    const config = parseRepoConfig('rulez:\n  disable: [secrets]\n', '.securityreview.yml');
    expect(config.warnings.join(' ')).toContain('unknown setting "rulez"');
    expect(config.warnings.join(' ')).toContain('rules');
  });

  it('warns about an unknown nested key', () => {
    const config = parseRepoConfig('paths:\n  excludes: [vendor/**]\n', '.securityreview.yml');
    expect(config.warnings.join(' ')).toContain('paths.excludes');
    // And the misspelling means nothing was excluded.
    expect(config.excludeGlobs).toHaveLength(0);
  });

  it('warns about a rule id that names no known category', () => {
    const config = parseRepoConfig('rules:\n  disable: [sqlinjection, secrets]\n', '.securityreview.yml');
    expect(config.warnings.join(' ')).toContain('sqlinjection');
    expect(config.disabledRules).toEqual(['secrets']);
  });

  it('warns about an invalid severity and keeps the default', () => {
    const config = parseRepoConfig('severity:\n  min: catastrophic\n', '.securityreview.yml');
    expect(config.minSeverity).toBeNull();
    expect(config.warnings.join(' ')).toContain('catastrophic');
  });

  it('accepts never for fail-on', () => {
    expect(parseRepoConfig('severity:\n  fail-on: never\n', 'c.yml').failOnSeverity).toBe('never');
  });

  it('warns about a non-boolean where a boolean belongs', () => {
    const config = parseRepoConfig('paths:\n  include-tests: yes-please\n', '.securityreview.yml');
    expect(config.includeTests).toBeNull();
    expect(config.warnings.join(' ')).toContain('include-tests');
  });

  it('warns about an out-of-range number', () => {
    const config = parseRepoConfig('inline:\n  max-comments: 5000\n', '.securityreview.yml');
    expect(config.inline.maxComments).toBeNull();
    expect(config.warnings.join(' ')).toContain('between 0 and 100');
  });

  it('accepts a single string where a list is expected', () => {
    const config = parseRepoConfig('paths:\n  exclude: vendor/**\n', '.securityreview.yml');
    expect(config.excludeGlobs).toHaveLength(1);
  });

  it('warns about a non-string list entry', () => {
    const config = parseRepoConfig('paths:\n  exclude: [vendor/**, 42]\n', '.securityreview.yml');
    expect(config.excludeGlobs).toHaveLength(1);
    expect(config.warnings.join(' ')).toContain('non-string');
  });

  it('warns about an unrecognised version but still reads the file', () => {
    const config = parseRepoConfig('version: 7\nseverity:\n  min: high\n', '.securityreview.yml');
    expect(config.minSeverity).toBe('high');
    expect(config.warnings.join(' ')).toContain('version 7');
  });
});

describe('pathInScope', () => {
  it('excludes matching paths', () => {
    const config = parseRepoConfig('paths:\n  exclude: [vendor/**]\n', 'c.yml');
    expect(pathInScope(config, 'vendor/lib.js')).toBe(false);
    expect(pathInScope(config, 'src/app.ts')).toBe(true);
  });

  it('restricts to the include list when one is given', () => {
    const config = parseRepoConfig('paths:\n  include: [src/**]\n', 'c.yml');
    expect(pathInScope(config, 'src/app.ts')).toBe(true);
    expect(pathInScope(config, 'scripts/deploy.sh')).toBe(false);
  });

  it('lets exclude win over include', () => {
    const config = parseRepoConfig(
      'paths:\n  include: [src/**]\n  exclude: [src/generated/**]\n',
      'c.yml',
    );
    expect(pathInScope(config, 'src/app.ts')).toBe(true);
    expect(pathInScope(config, 'src/generated/schema.ts')).toBe(false);
  });

  it('includes everything when neither list is given', () => {
    expect(pathInScope(emptyRepoConfig(), 'anything.ts')).toBe(true);
  });
});

describe('mergeRepoConfig', () => {
  it('is a no-op when no config file exists', () => {
    const base = baseConfig();
    const merged = mergeRepoConfig(base, emptyRepoConfig());
    expect(merged.config).toBe(base);
    expect(merged.warnings).toEqual([]);
  });

  it('lets the repository tighten the merge gate', () => {
    const merged = mergeRepoConfig(
      baseConfig({ failOnSeverity: 'high' }),
      parseRepoConfig('severity:\n  fail-on: medium\n', 'c.yml'),
    );
    expect(merged.config.review.failOnSeverity).toBe('medium');
    expect(merged.warnings).toEqual([]);
  });

  it('refuses to let the repository loosen the merge gate', () => {
    const merged = mergeRepoConfig(
      baseConfig({ failOnSeverity: 'high' }),
      parseRepoConfig('severity:\n  fail-on: critical\n', 'c.yml'),
    );
    expect(merged.config.review.failOnSeverity).toBe('high');
    expect(merged.warnings.join(' ')).toContain('cannot be looser');
  });

  it('refuses to let the repository remove the gate entirely', () => {
    const merged = mergeRepoConfig(
      baseConfig({ failOnSeverity: 'high' }),
      parseRepoConfig('severity:\n  fail-on: never\n', 'c.yml'),
    );
    expect(merged.config.review.failOnSeverity).toBe('high');
    expect(merged.warnings.join(' ')).toContain('cannot be looser');
  });

  it('merges disabled rules rather than replacing them', () => {
    const base = baseConfig();
    base.review.disabledRules = ['secrets'];
    const merged = mergeRepoConfig(base, parseRepoConfig('rules:\n  disable: [dependencies]\n', 'c.yml'));
    expect(merged.config.review.disabledRules.sort()).toEqual(['dependencies', 'secrets']);
  });

  it('applies inline settings', () => {
    const merged = mergeRepoConfig(
      baseConfig(),
      parseRepoConfig('inline:\n  enabled: false\n  max-comments: 3\n  min-severity: critical\n', 'c.yml'),
    );
    expect(merged.config.review.inlineComments).toBe(false);
    expect(merged.config.review.maxInlineComments).toBe(3);
    expect(merged.config.review.inlineMinSeverity).toBe('critical');
  });

  it('lets a repository switch triage off', () => {
    const base = baseConfig();
    base.ai.enabled = true;
    const merged = mergeRepoConfig(base, parseRepoConfig('triage:\n  enabled: false\n', 'c.yml'));
    expect(merged.config.ai.enabled).toBe(false);
  });

  it('does not let a repository switch triage on when the service has no model', () => {
    const base = baseConfig();
    base.ai.enabled = false;
    const merged = mergeRepoConfig(base, parseRepoConfig('triage:\n  enabled: true\n', 'c.yml'));
    expect(merged.config.ai.enabled).toBe(false);
    expect(merged.warnings.join(' ')).toContain('no model configured');
  });

  it('carries parse warnings through', () => {
    const merged = mergeRepoConfig(baseConfig(), parseRepoConfig('nonsense: 1\n', 'c.yml'));
    expect(merged.warnings.join(' ')).toContain('unknown setting');
  });

  it('does not mutate the config it was given', () => {
    const base = baseConfig({ failOnSeverity: 'high' });
    const before = JSON.stringify(base.review);
    mergeRepoConfig(base, parseRepoConfig('severity:\n  min: critical\n', 'c.yml'));
    expect(JSON.stringify(base.review)).toBe(before);
  });
});

describe('the shipped example config', () => {
  it('parses with no warnings', () => {
    // A documented example that no longer validates is worse than no example,
    // so the file itself is part of the test suite.
    const text = readFileSync('.securityreview.example.yml', 'utf8');
    const config = parseRepoConfig(text, '.securityreview.example.yml');
    expect(config.warnings).toEqual([]);
    expect(config.present).toBe(true);
  });

  it('exercises every documented section', () => {
    const text = readFileSync('.securityreview.example.yml', 'utf8');
    const config = parseRepoConfig(text, '.securityreview.example.yml');
    expect(config.excludeGlobs.length).toBeGreaterThan(0);
    expect(config.includeTests).toBe(false);
    expect(config.disabledRules.length).toBeGreaterThan(0);
    expect(config.minSeverity).not.toBeNull();
    expect(config.failOnSeverity).not.toBeNull();
    expect(config.severityOverrides.size).toBeGreaterThan(0);
    expect(config.inline.enabled).not.toBeNull();
    expect(config.triage.enabled).not.toBeNull();
  });
});
