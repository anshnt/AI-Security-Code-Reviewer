import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildTarget } from '../src/analysis/engine';
import type { Finding, ScanTarget } from '../src/analysis/types';
import { buildExcerpts, scrubCredentials } from '../src/ai/excerpt';
import {
  adjustSeverity,
  parseResponse,
  renderPrompt,
  selectForTriage,
  triage,
  type TriageOptions,
} from '../src/ai/triage';

/**
 * The triage pass talks to a network service, so these tests stub the SDK
 * module. That leaves three things worth verifying, and they are the three
 * things that could hurt someone: what gets sent, what happens when the service
 * misbehaves, and how much the response is allowed to change.
 */

const VULNERABLE = [
  'import { db } from "./db";',
  '',
  'export async function getInvoice(req, res) {',
  '  const id = req.params.id;',
  '  const rows = await db.query(`SELECT * FROM invoices WHERE id = ${id}`);',
  '  res.json(rows);',
  '}',
].join('\n');

function target(content = VULNERABLE, filePath = 'src/invoices.ts'): ScanTarget {
  return buildTarget({ filePath, content, status: 'modified', changedLines: null });
}

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'sql-injection/interpolated-query',
    category: 'sql-injection',
    severity: 'critical',
    confidence: 'high',
    title: 'SQL query built by string interpolation',
    description: 'Interpolated request data into SQL.',
    remediation: 'Bind the value as a parameter.',
    filePath: 'src/invoices.ts',
    line: 5,
    snippet: 'db.query(`SELECT * FROM invoices WHERE id = ${id}`)',
    fingerprint: 'fp-sql',
    ...overrides,
  };
}

function options(overrides: Partial<TriageOptions> = {}): TriageOptions {
  return {
    apiKey: 'test-key',
    model: 'test-model',
    timeoutMs: 5000,
    maxRetries: 0,
    minSeverity: 'medium',
    maxFindings: 25,
    contextLines: 3,
    maxLinesPerFile: 200,
    effort: 'high',
    maxTokens: 4000,
    ...overrides,
  };
}

describe('scrubCredentials', () => {
  it('removes provider-format tokens', () => {
    const text = 'const key = "AKIAIOSFODNN7EXAMPLE";';
    expect(scrubCredentials(text)).toBe('const key = "[redacted]";');
  });

  it('removes the value of a credential assignment but keeps the shape', () => {
    const out = scrubCredentials('const apiSecret = "Zq7#vR2pLm9$Kd4Xw8Tb6Nj1";');
    expect(out).toContain('apiSecret');
    expect(out).toContain('[redacted]');
    expect(out).not.toContain('Zq7#vR2pLm9');
  });

  it('removes a password from a connection string', () => {
    const out = scrubCredentials('postgres://svc:sup3rSecret@db.internal:5432/app');
    expect(out).not.toContain('sup3rSecret');
    expect(out).toContain('postgres://svc:[redacted]@db.internal');
  });

  it('removes a private key block', () => {
    const out = scrubCredentials(
      '-----BEGIN RSA PRIVATE KEY-----\nMIIEabc123\n-----END RSA PRIVATE KEY-----',
    );
    expect(out).toBe('[redacted]');
  });

  it('leaves ordinary code alone', () => {
    const code = 'const total = price * quantity;';
    expect(scrubCredentials(code)).toBe(code);
  });
});

describe('buildExcerpts', () => {
  it('numbers the lines it includes', () => {
    const excerpt = buildExcerpts(target(), [finding()], { contextLines: 2, maxLinesPerFile: 100 })!;
    expect(excerpt.text).toContain('    5  ');
    expect(excerpt.startLine).toBe(3);
    expect(excerpt.endLine).toBe(7);
  });

  it('merges overlapping windows instead of repeating lines', () => {
    const excerpt = buildExcerpts(
      target(),
      [finding(), finding({ fingerprint: 'fp-2', line: 6 })],
      { contextLines: 3, maxLinesPerFile: 100 },
    )!;
    const occurrences = excerpt.text.split('\n').filter((line) => line.includes('res.json(rows)'));
    expect(occurrences).toHaveLength(1);
  });

  it('separates distant windows with an elision marker', () => {
    const long = Array.from({ length: 120 }, (_, index) => `const line${index} = ${index};`).join('\n');
    const excerpt = buildExcerpts(
      target(long),
      [finding({ line: 5 }), finding({ fingerprint: 'fp-2', line: 100 })],
      { contextLines: 2, maxLinesPerFile: 100 },
    )!;
    expect(excerpt.text).toContain('...');
  });

  it('caps the number of lines and says it truncated', () => {
    const long = Array.from({ length: 400 }, (_, index) => `const line${index} = ${index};`).join('\n');
    const excerpt = buildExcerpts(target(long), [finding({ line: 200 })], {
      contextLines: 150,
      maxLinesPerFile: 20,
    })!;
    expect(excerpt.text.split('\n').filter((l) => /^\s*\d+\s/.test(l))).toHaveLength(20);
    expect(excerpt.text).toContain('truncated');
  });

  it('scrubs credentials out of the excerpt', () => {
    const source = ['const a = 1;', 'const key = "AKIAIOSFODNN7EXAMPLE";', 'const b = 2;'].join('\n');
    const excerpt = buildExcerpts(target(source), [finding({ line: 2 })], {
      contextLines: 1,
      maxLinesPerFile: 100,
    })!;
    expect(excerpt.text).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(excerpt.text).toContain('[redacted]');
  });

  it('returns null when there is nothing to send', () => {
    expect(buildExcerpts(target(), [], { contextLines: 3, maxLinesPerFile: 100 })).toBeNull();
  });
});

describe('selectForTriage', () => {
  it('drops findings below the severity floor', () => {
    const chosen = selectForTriage(
      [finding(), finding({ fingerprint: 'fp-low', severity: 'low' })],
      options({ minSeverity: 'high' }),
    );
    expect(chosen.map((f) => f.fingerprint)).toEqual(['fp-sql']);
  });

  it('never sends a provider-format secret match', () => {
    const chosen = selectForTriage(
      [
        finding({ fingerprint: 'fp-aws', category: 'secrets', ruleId: 'secrets/aws-access-key-id' }),
        finding(),
      ],
      options(),
    );
    expect(chosen.map((f) => f.fingerprint)).toEqual(['fp-sql']);
  });

  it('does send a generic hardcoded-credential finding, where judgement helps', () => {
    const chosen = selectForTriage(
      [finding({ fingerprint: 'fp-generic', category: 'secrets', ruleId: 'secrets/hardcoded-credential', severity: 'high' })],
      options(),
    );
    expect(chosen.map((f) => f.fingerprint)).toEqual(['fp-generic']);
  });

  it('prefers low-confidence findings within a severity band', () => {
    const chosen = selectForTriage(
      [
        finding({ fingerprint: 'sure', confidence: 'high' }),
        finding({ fingerprint: 'unsure', confidence: 'low' }),
      ],
      options(),
    );
    expect(chosen.map((f) => f.fingerprint)).toEqual(['unsure', 'sure']);
  });

  it('honours the per-review cap', () => {
    const many = Array.from({ length: 40 }, (_, index) => finding({ fingerprint: `fp-${index}` }));
    expect(selectForTriage(many, options({ maxFindings: 5 }))).toHaveLength(5);
  });
});

describe('renderPrompt', () => {
  it('includes the fingerprint, the rule and the excerpt', () => {
    const excerpt = buildExcerpts(target(), [finding()], { contextLines: 2, maxLinesPerFile: 100 })!;
    const prompt = renderPrompt(excerpt, [finding()]);
    expect(prompt).toContain('fp-sql');
    expect(prompt).toContain('sql-injection/interpolated-query');
    expect(prompt).toContain('src/invoices.ts');
    expect(prompt).toContain('db.query');
  });
});

describe('adjustSeverity', () => {
  it('ignores an adjustment that is not high confidence', () => {
    expect(adjustSeverity('critical', 'low', 'medium')).toBe('critical');
    expect(adjustSeverity('critical', 'low', 'low')).toBe('critical');
  });

  it('allows a single step on high confidence', () => {
    expect(adjustSeverity('critical', 'high', 'high')).toBe('high');
    expect(adjustSeverity('medium', 'high', 'high')).toBe('high');
  });

  it('clamps a larger jump to one step', () => {
    expect(adjustSeverity('critical', 'info', 'high')).toBe('high');
    expect(adjustSeverity('low', 'critical', 'high')).toBe('medium');
  });

  it('ignores a severity outside the scale', () => {
    expect(adjustSeverity('high', 'catastrophic', 'high')).toBe('high');
    expect(adjustSeverity('high', 42, 'high')).toBe('high');
  });
});

describe('parseResponse', () => {
  function message(content: unknown[]): Parameters<typeof parseResponse>[0] {
    return { content } as Parameters<typeof parseResponse>[0];
  }

  const toolBlock = (findings: unknown[]) => ({
    type: 'tool_use',
    name: 'report_triage',
    input: { findings },
  });

  it('reads a well-formed tool call', () => {
    const results = parseResponse(
      message([
        toolBlock([
          {
            fingerprint: 'fp-sql',
            verdict: 'confirmed',
            reasoning: 'Line 5 interpolates req.params.id straight into the statement.',
            fix: 'Pass id as a bound parameter.',
            confidence: 'high',
          },
        ]),
      ]),
      [finding()],
      'test-model',
    );
    const result = results.get('fp-sql')!;
    expect(result.verdict).toBe('confirmed');
    expect(result.fix).toBe('Pass id as a bound parameter.');
    expect(result.severity).toBe('critical');
    expect(result.model).toBe('test-model');
  });

  it('falls back to JSON in the text when no tool call is made', () => {
    const results = parseResponse(
      message([
        {
          type: 'text',
          text:
            'Here is my assessment:\n{"findings":[{"fingerprint":"fp-sql","verdict":"refuted",' +
            '"reasoning":"The id is validated against an allow-list on line 4.","confidence":"high"}]}',
        },
      ]),
      [finding()],
      'test-model',
    );
    expect(results.get('fp-sql')!.verdict).toBe('refuted');
  });

  it('drops a fingerprint that was not in the batch', () => {
    const results = parseResponse(
      message([
        toolBlock([
          { fingerprint: 'invented', verdict: 'confirmed', reasoning: 'x', confidence: 'high' },
        ]),
      ]),
      [finding()],
      'test-model',
    );
    expect(results.size).toBe(0);
  });

  it('drops an unrecognised verdict', () => {
    const results = parseResponse(
      message([
        toolBlock([
          { fingerprint: 'fp-sql', verdict: 'probably-fine', reasoning: 'x', confidence: 'high' },
        ]),
      ]),
      [finding()],
      'test-model',
    );
    expect(results.size).toBe(0);
  });

  it('drops a verdict with no reasoning', () => {
    const results = parseResponse(
      message([toolBlock([{ fingerprint: 'fp-sql', verdict: 'refuted', confidence: 'high' }])]),
      [finding()],
      'test-model',
    );
    expect(results.size).toBe(0);
  });

  it('records the original severity when it moves one', () => {
    const results = parseResponse(
      message([
        toolBlock([
          {
            fingerprint: 'fp-sql',
            verdict: 'likely',
            reasoning: 'Reachable only from an authenticated admin route.',
            severity: 'high',
            confidence: 'high',
          },
        ]),
      ]),
      [finding()],
      'test-model',
    );
    const result = results.get('fp-sql')!;
    expect(result.severity).toBe('high');
    expect(result.severityChangedFrom).toBe('critical');
  });

  it('returns nothing for a malformed response rather than throwing', () => {
    expect(parseResponse(message([{ type: 'text', text: 'not json at all' }]), [finding()], 'm').size).toBe(0);
    expect(parseResponse(message([]), [finding()], 'm').size).toBe(0);
  });
});

/**
 * The pass as a whole, with the SDK stubbed. These are the cases where a
 * failure must not degrade the review.
 */
describe('triage', () => {
  afterEach(() => {
    vi.resetModules();
    vi.restoreAllMocks();
  });

  it('does nothing when no finding clears the severity floor', async () => {
    const pass = await triage(
      [finding({ severity: 'low' })],
      new Map([['src/invoices.ts', target()]]),
      options({ minSeverity: 'high' }),
    );
    expect(pass.triagedCount).toBe(0);
    expect(pass.findings[0]!.severity).toBe('low');
  });

  it('returns the findings untouched when there is no credential', async () => {
    const pass = await triage(
      [finding()],
      new Map([['src/invoices.ts', target()]]),
      options({ apiKey: '' }),
    );
    expect(pass.error).toContain('no API key');
    expect(pass.findings).toHaveLength(1);
    expect(pass.findings[0]!.triage).toBeUndefined();
    expect(pass.findings[0]!.severity).toBe('critical');
  });

  it('returns the findings untouched when the file content is unavailable', async () => {
    const pass = await triage([finding()], new Map(), options());
    expect(pass.triagedCount).toBe(0);
    expect(pass.findings[0]!.triage).toBeUndefined();
  });
});
