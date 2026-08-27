import { gunzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { scan } from '../src/analysis/engine';
import type { Severity } from '../src/analysis/types';
import type { TriagedFinding } from '../src/ai/triage';
import {
  capResults,
  MAX_RESULTS_PER_RULE,
  renderSarif,
  SARIF_VERSION,
  toSarif,
  type SarifOptions,
} from '../src/report/sarif';

/**
 * These tests are mostly about GitHub's contract rather than the SARIF spec.
 * A document can be perfectly valid SARIF and still produce alerts that reopen
 * on every push, or show a severity that contradicts the pull request comment -
 * so the assertions target the fields that decide those behaviours.
 */

const OPTIONS: SarifOptions = {
  toolName: 'security-review',
  toolVersion: '0.1.0',
  informationUri: 'https://example.com/tool',
};

function finding(overrides: Partial<TriagedFinding> = {}): TriagedFinding {
  return {
    ruleId: 'sql-injection/interpolated-query',
    category: 'sql-injection',
    severity: 'critical',
    confidence: 'high',
    title: 'SQL query built by string interpolation',
    description: 'Interpolated request data into SQL.',
    remediation: 'Bind the value as a parameter.',
    filePath: 'src/invoices.ts',
    line: 12,
    snippet: 'db.query(`... ${id}`)',
    cwe: ['CWE-89'],
    fingerprint: 'abc123def456',
    ...overrides,
  } as TriagedFinding;
}

interface Run {
  tool: { driver: { name: string; version: string; informationUri: string; rules: Rule[] } };
  results: Result[];
  automationDetails?: { id: string };
  originalUriBaseIds?: Record<string, { uri: string }>;
  invocations?: { toolExecutionNotifications: { message: { text: string } }[] }[];
}
interface Rule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help: { text: string; markdown: string };
  defaultConfiguration: { level: string };
  properties: Record<string, unknown>;
}
interface Result {
  ruleId: string;
  ruleIndex: number;
  level: string;
  message: { text: string };
  locations: {
    physicalLocation: {
      artifactLocation: { uri: string; uriBaseId: string };
      region: { startLine: number; endLine?: number; snippet: { text: string } };
    };
  }[];
  partialFingerprints: Record<string, string>;
  properties: Record<string, unknown>;
}

function run(findings: TriagedFinding[], options: Partial<SarifOptions> = {}): Run {
  return toSarif(findings, { ...OPTIONS, ...options }).runs[0] as Run;
}

describe('document shape', () => {
  it('declares the schema and version GitHub expects', () => {
    const document = toSarif([finding()], OPTIONS);
    expect(document.version).toBe(SARIF_VERSION);
    expect(document.$schema).toContain('sarif-2.1.0');
    expect(document.runs).toHaveLength(1);
  });

  it('identifies the tool', () => {
    const driver = run([finding()]).tool.driver;
    expect(driver).toMatchObject({
      name: 'security-review',
      version: '0.1.0',
      informationUri: 'https://example.com/tool',
    });
  });

  it('sets an automation id when one is given', () => {
    expect(run([finding()], { automationId: 'security-review/pr-11' }).automationDetails).toEqual({
      id: 'security-review/pr-11',
    });
  });

  it('produces a valid empty run when there is nothing to report', () => {
    const output = run([]);
    expect(output.results).toEqual([]);
    expect(output.tool.driver.rules).toEqual([]);
  });

  it('renders as parseable JSON ending in a newline', () => {
    const text = renderSarif([finding()], OPTIONS);
    expect(text.endsWith('\n')).toBe(true);
    expect(() => JSON.parse(text)).not.toThrow();
  });
});

describe('alert tracking', () => {
  it('carries the content fingerprint, which is what stops alerts reopening', () => {
    // Without partialFingerprints GitHub matches by location, so an alert
    // closes and reopens whenever anything above it shifts a line - and a
    // dismissal does not survive.
    const result = run([finding()]).results[0]!;
    expect(result.partialFingerprints.securityReviewFingerprint).toBe('abc123def456');
  });

  it('keeps the fingerprint stable when the line moves', () => {
    const before = run([finding({ line: 12 })]).results[0]!;
    const after = run([finding({ line: 48 })]).results[0]!;
    expect(after.partialFingerprints).toEqual(before.partialFingerprints);
  });
});

describe('severity mapping', () => {
  const cases: { severity: Severity; level: string; band: [number, number] | null }[] = [
    { severity: 'critical', level: 'error', band: [9.0, 10] },
    { severity: 'high', level: 'error', band: [7.0, 8.9] },
    { severity: 'medium', level: 'warning', band: [4.0, 6.9] },
    { severity: 'low', level: 'note', band: [0.1, 3.9] },
    { severity: 'info', level: 'none', band: null },
  ];

  for (const { severity, level, band } of cases) {
    it(`maps ${severity} into the band GitHub calls ${band ? severity : 'not a security alert'}`, () => {
      const output = run([finding({ severity, fingerprint: `fp-${severity}` })]);
      const rule = output.tool.driver.rules[0]!;
      expect(rule.defaultConfiguration.level).toBe(level);
      if (band === null) {
        // GitHub's lowest security band starts at 0.1, so scoring an
        // informational finding would file it as a low severity security alert.
        expect(rule.properties['security-severity']).toBeUndefined();
      } else {
        const score = Number(rule.properties['security-severity']);
        expect(score).toBeGreaterThanOrEqual(band[0]);
        expect(score).toBeLessThanOrEqual(band[1]);
      }
    });
  }

  it('takes the worst severity when one rule fires at several', () => {
    // GitHub reads severity from the rule, not the result, so a rule affected by
    // a severity override has to settle on one number - and understating it is
    // the error that matters.
    const output = run([
      finding({ severity: 'low', fingerprint: 'a', line: 1 }),
      finding({ severity: 'critical', fingerprint: 'b', line: 2 }),
    ]);
    expect(output.tool.driver.rules).toHaveLength(1);
    expect(Number(output.tool.driver.rules[0]!.properties['security-severity'])).toBeGreaterThanOrEqual(9);
    expect(output.tool.driver.rules[0]!.defaultConfiguration.level).toBe('error');
  });

  it('still records the real severity on each result', () => {
    const output = run([
      finding({ severity: 'low', fingerprint: 'a', line: 1 }),
      finding({ severity: 'critical', fingerprint: 'b', line: 2 }),
    ]);
    expect(output.results.map((result) => result.properties.severity)).toEqual(['low', 'critical']);
  });

  it('does not make every finding an error', () => {
    // A tool where a predictable temp file fails the build gets switched off.
    const output = run([finding({ severity: 'low', fingerprint: 'a' })]);
    expect(output.results[0]!.level).toBe('note');
  });
});

describe('rule metadata', () => {
  it('emits a rule only for rules that fired', () => {
    const output = run([finding()]);
    expect(output.tool.driver.rules).toHaveLength(1);
    expect(output.tool.driver.rules[0]!.id).toBe('sql-injection/interpolated-query');
  });

  it('orders rules deterministically, so two runs are byte-identical', () => {
    const findings = [
      finding({ ruleId: 'secrets/aws-access-key-id', category: 'secrets', fingerprint: 'a' }),
      finding({ ruleId: 'dangerous-api/eval', category: 'dangerous-api', fingerprint: 'b' }),
    ];
    const first = renderSarif(findings, OPTIONS);
    const second = renderSarif([...findings].reverse(), OPTIONS);
    // Reversing the input changes result order but not the rule table, so the
    // rule indices stay meaningful.
    expect(JSON.parse(first).runs[0].tool.driver.rules.map((r: Rule) => r.id)).toEqual(
      JSON.parse(second).runs[0].tool.driver.rules.map((r: Rule) => r.id),
    );
  });

  it('points every result at the right rule index', () => {
    const output = run([
      finding({ ruleId: 'secrets/aws-access-key-id', category: 'secrets', fingerprint: 'a' }),
      finding({ ruleId: 'dangerous-api/eval', category: 'dangerous-api', fingerprint: 'b' }),
    ]);
    for (const result of output.results) {
      expect(output.tool.driver.rules[result.ruleIndex]!.id).toBe(result.ruleId);
    }
  });

  it('tags the security category and the CWE', () => {
    const tags = run([finding()]).tool.driver.rules[0]!.properties.tags as string[];
    expect(tags).toContain('security');
    expect(tags).toContain('category/sql-injection');
    expect(tags).toContain('external/cwe/cwe-89');
  });

  it('carries the fix into the help text', () => {
    const help = run([finding()]).tool.driver.rules[0]!.help;
    expect(help.text).toContain('Bind the value as a parameter.');
    expect(help.markdown).toContain('**How to fix.**');
  });

  it('reports precision from the analyzer confidence', () => {
    expect(run([finding({ confidence: 'low' })]).tool.driver.rules[0]!.properties.precision).toBe('low');
  });
});

describe('locations', () => {
  it('anchors to the file and line', () => {
    const location = run([finding()]).results[0]!.locations[0]!.physicalLocation;
    expect(location.artifactLocation.uri).toBe('src/invoices.ts');
    expect(location.region.startLine).toBe(12);
    expect(location.region.snippet.text).toBe('db.query(`... ${id}`)');
  });

  it('includes an end line only when it adds information', () => {
    expect(run([finding()]).results[0]!.locations[0]!.physicalLocation.region.endLine).toBeUndefined();
    expect(
      run([finding({ endLine: 15 })]).results[0]!.locations[0]!.physicalLocation.region.endLine,
    ).toBe(15);
  });

  it('never emits a line below one', () => {
    expect(run([finding({ line: 0 })]).results[0]!.locations[0]!.physicalLocation.region.startLine).toBe(1);
  });

  it('declares a URI base only when a working directory is given', () => {
    expect(run([finding()]).originalUriBaseIds).toBeUndefined();
    expect(run([finding()], { workingDirectory: 'file:///repo' }).originalUriBaseIds).toEqual({
      '%SRCROOT%': { uri: 'file:///repo/' },
    });
  });
});

describe('triage in the message', () => {
  it('prefers the reviewed explanation', () => {
    const output = run([
      finding({
        triage: {
          verdict: 'confirmed',
          reasoning: 'Line 12 splices req.params.id into the statement.',
          severity: 'critical',
          confidence: 'high',
          model: 'test-model',
        },
      }),
    ]);
    expect(output.results[0]!.message.text).toContain('Line 12 splices req.params.id');
    expect(output.results[0]!.properties.reviewVerdict).toBe('confirmed');
  });

  it('says up front when a finding was refuted', () => {
    // Someone reading the Security tab has no pull-request context, so a
    // refuted finding has to explain itself there.
    const output = run([
      finding({
        triage: {
          verdict: 'refuted',
          reasoning: 'Validated against a numeric allow-list on line 10.',
          severity: 'critical',
          confidence: 'high',
          model: 'm',
        },
      }),
    ]);
    expect(output.results[0]!.message.text).toContain('Judged a false positive on review');
    expect(output.results[0]!.message.text).toContain('numeric allow-list');
  });

  it('falls back to the rule description with no triage', () => {
    expect(run([finding()]).results[0]!.message.text).toContain('Interpolated request data into SQL.');
  });
});

describe('GitHub result limits', () => {
  it('caps results per rule', () => {
    const many = Array.from({ length: MAX_RESULTS_PER_RULE + 50 }, (_, index) =>
      finding({ fingerprint: `fp-${index}`, line: index + 1 }),
    );
    expect(capResults(many)).toHaveLength(MAX_RESULTS_PER_RULE);
  });

  it('keeps findings from other rules when one rule saturates', () => {
    const many = [
      ...Array.from({ length: MAX_RESULTS_PER_RULE + 10 }, (_, index) =>
        finding({ fingerprint: `a-${index}`, line: index + 1 }),
      ),
      finding({ ruleId: 'dangerous-api/eval', category: 'dangerous-api', fingerprint: 'other' }),
    ];
    const capped = capResults(many);
    expect(capped.some((f) => f.ruleId === 'dangerous-api/eval')).toBe(true);
  });

  it('says so in the run when results were dropped', () => {
    const many = Array.from({ length: MAX_RESULTS_PER_RULE + 5 }, (_, index) =>
      finding({ fingerprint: `fp-${index}`, line: index + 1 }),
    );
    const output = run(many);
    const note = output.invocations?.[0]?.toolExecutionNotifications[0]?.message.text ?? '';
    expect(note).toContain('omitted');
  });

  it('adds no notification when nothing was dropped', () => {
    expect(run([finding()]).invocations).toBeUndefined();
  });
});

describe('end to end from a real scan', () => {
  it('turns analyzer output into a document GitHub would accept', () => {
    const summary = scan([
      {
        filePath: 'src/app.ts',
        content: [
          'export async function get(req, res) {',
          '  const id = req.params.id;',
          '  return db.query(`SELECT * FROM t WHERE id = ${id}`);',
          '}',
        ].join('\n'),
        status: 'modified',
        changedLines: null,
      },
    ]);

    const document = toSarif(summary.findings, OPTIONS);
    const output = document.runs[0] as Run;

    expect(output.results.length).toBeGreaterThan(0);
    for (const result of output.results) {
      expect(typeof result.ruleId).toBe('string');
      expect(result.message.text.length).toBeGreaterThan(0);
      const location = result.locations[0]!.physicalLocation;
      // Relative, because GitHub resolves paths against the repository root.
      expect(location.artifactLocation.uri.startsWith('/')).toBe(false);
      expect(location.region.startLine).toBeGreaterThan(0);
      expect(result.partialFingerprints.securityReviewFingerprint).toBeTruthy();
      expect(output.tool.driver.rules[result.ruleIndex]!.id).toBe(result.ruleId);
    }
  });

  it('survives a gzip round trip, which is how the upload API takes it', () => {
    const text = renderSarif([finding()], OPTIONS);
    const encoded = Buffer.from(text, 'utf8');
    const { gzipSync } = require('node:zlib') as typeof import('node:zlib');
    const restored = gunzipSync(gzipSync(encoded)).toString('utf8');
    expect(JSON.parse(restored)).toEqual(JSON.parse(text));
  });
});
