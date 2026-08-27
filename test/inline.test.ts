import { describe, expect, it } from 'vitest';
import type { Finding } from '../src/analysis/types';
import type { TriagedFinding } from '../src/ai/triage';
import { fingerprintMarker, planInlineComments, renderInlineBody, type InlineOptions } from '../src/github/inline';

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
    fingerprint: 'aaaa1111',
    ...overrides,
  } as TriagedFinding;
}

function options(overrides: Partial<InlineOptions> = {}): InlineOptions {
  return {
    commentableLines: new Map([['src/invoices.ts', new Set([10, 11, 12, 13, 14])]]),
    existingBodies: [],
    maxComments: 15,
    minSeverity: 'medium',
    repositoryFullName: 'acme/app',
    ...overrides,
  };
}

describe('planInlineComments', () => {
  it('anchors a finding on a line inside the diff', () => {
    const plan = planInlineComments([finding()], options());
    expect(plan.comments).toHaveLength(1);
    expect(plan.comments[0]).toMatchObject({ path: 'src/invoices.ts', line: 12 });
    expect(plan.deferred).toHaveLength(0);
  });

  it('defers a finding on a line the diff does not show', () => {
    const plan = planInlineComments([finding({ line: 400 })], options());
    expect(plan.comments).toHaveLength(0);
    expect(plan.deferred).toHaveLength(1);
  });

  it('defers a finding in a file with no patch', () => {
    const plan = planInlineComments([finding({ filePath: 'src/other.ts' })], options());
    expect(plan.comments).toHaveLength(0);
    expect(plan.deferred).toHaveLength(1);
  });

  it('skips a finding that already has a comment', () => {
    const plan = planInlineComments([finding()], options({
      existingBodies: [`${fingerprintMarker('aaaa1111')}\nsomething said earlier`],
    }));
    expect(plan.comments).toHaveLength(0);
    expect(plan.alreadyPosted).toBe(1);
    // Not deferred either: it is already visible on the line.
    expect(plan.deferred).toHaveLength(0);
  });

  it('is not confused by an unrelated comment on the same pull request', () => {
    const plan = planInlineComments([finding()], options({
      existingBodies: ['Looks good to me', `${fingerprintMarker('bbbb2222')} another finding`],
    }));
    expect(plan.comments).toHaveLength(1);
  });

  it('defers findings below the inline severity floor', () => {
    const plan = planInlineComments(
      [finding({ severity: 'low', fingerprint: 'low1' }), finding()],
      options({ minSeverity: 'high' }),
    );
    expect(plan.comments).toHaveLength(1);
    expect(plan.comments[0]!.body).toContain('SQL query');
    expect(plan.deferred.map((f) => f.fingerprint)).toEqual(['low1']);
  });

  it('never comments inline on a refuted finding', () => {
    const plan = planInlineComments(
      [
        finding({
          fingerprint: 'refuted1',
          triage: {
            verdict: 'refuted',
            reasoning: 'Validated upstream.',
            severity: 'critical',
            confidence: 'high',
            model: 'm',
          },
        }),
      ],
      options(),
    );
    expect(plan.comments).toHaveLength(0);
    expect(plan.deferred).toHaveLength(1);
  });

  it('caps the number of comments and defers the rest', () => {
    const lines = new Set(Array.from({ length: 30 }, (_, index) => index + 1));
    const many = Array.from({ length: 20 }, (_, index) =>
      finding({ fingerprint: `fp-${index}`, line: index + 1 }),
    );
    const plan = planInlineComments(many, options({
      maxComments: 5,
      commentableLines: new Map([['src/invoices.ts', lines]]),
    }));
    expect(plan.comments).toHaveLength(5);
    expect(plan.deferred).toHaveLength(15);
  });

  it('preserves the order it was given, which is worst-first', () => {
    const lines = new Set([1, 2, 3]);
    const plan = planInlineComments(
      [
        finding({ fingerprint: 'crit', severity: 'critical', line: 1 }),
        finding({ fingerprint: 'high', severity: 'high', line: 2 }),
        finding({ fingerprint: 'med', severity: 'medium', line: 3 }),
      ],
      options({ maxComments: 2, commentableLines: new Map([['src/invoices.ts', lines]]) }),
    );
    expect(plan.comments.map((comment) => comment.line)).toEqual([1, 2]);
    expect(plan.deferred.map((f) => f.fingerprint)).toEqual(['med']);
  });
});

describe('renderInlineBody', () => {
  it('carries a hidden fingerprint so the next push can skip it', () => {
    const body = renderInlineBody(finding(), options());
    expect(body).toContain('<!-- security-review:finding:aaaa1111 -->');
  });

  it('does not repeat the snippet, because the reader is looking at the line', () => {
    const body = renderInlineBody(finding(), options());
    expect(body).not.toContain('db.query(`... ${id}`)');
  });

  it('states the fix and how to disagree', () => {
    const body = renderInlineBody(finding(), options());
    expect(body).toContain('**Fix.** Bind the value as a parameter.');
    expect(body).toContain('security-review-ignore sql-injection/interpolated-query');
  });

  it('includes the rule, severity, category and CWE', () => {
    const body = renderInlineBody(finding(), options());
    expect(body).toContain('critical severity');
    expect(body).toContain('SQL Injection');
    expect(body).toContain('sql-injection/interpolated-query');
    expect(body).toContain('CWE-89');
  });

  it('prefers the reviewed explanation and fix when triage ran', () => {
    const body = renderInlineBody(
      finding({
        triage: {
          verdict: 'confirmed',
          reasoning: 'Line 12 splices req.params.id into the statement.',
          fix: 'Pass id in the parameter array.',
          severity: 'critical',
          confidence: 'high',
          model: 'test-model',
        },
      }),
      options(),
    );
    expect(body).toContain('Line 12 splices req.params.id into the statement.');
    expect(body).toContain('**Fix.** Pass id in the parameter array.');
    expect(body).not.toContain('Interpolated request data into SQL.');
  });

  it('notes a severity adjustment made on review', () => {
    const body = renderInlineBody(
      finding({
        severity: 'high',
        triage: {
          verdict: 'likely',
          reasoning: 'Admin-only route.',
          severity: 'high',
          severityChangedFrom: 'critical',
          confidence: 'high',
          model: 'm',
        },
      }),
      options(),
    );
    expect(body).toContain('severity moved from critical on review');
  });

  it('links to the dashboard only when one is configured', () => {
    expect(renderInlineBody(finding(), options())).not.toContain('Vulnerability trends');
    expect(
      renderInlineBody(finding(), options({ dashboardUrl: 'https://review.example.com' })),
    ).toContain('https://review.example.com/?repo=acme%2Fapp');
  });
});

describe('fingerprintMarker', () => {
  it('round-trips through the planner', () => {
    const marker = fingerprintMarker('deadbeef1234');
    const plan = planInlineComments(
      [finding({ fingerprint: 'deadbeef1234' })],
      options({ existingBodies: [marker] }),
    );
    expect(plan.alreadyPosted).toBe(1);
  });
});

/** A guard against the planner silently accepting a non-triaged Finding shape. */
describe('type compatibility', () => {
  it('accepts a plain finding with no triage field', () => {
    const plain: Finding = finding();
    expect(planInlineComments([plain], options()).comments).toHaveLength(1);
  });
});
