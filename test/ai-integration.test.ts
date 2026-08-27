import { beforeEach, describe, expect, it } from 'vitest';
import { loadConfig, type AppConfig } from '../src/config';
import type { GitHubClient, PullRequestFile, PullRequestInfo } from '../src/github/client';
import { PullRequestReviewer } from '../src/github/reviewer';
import { ReviewStore } from '../src/storage/database';
import { clearModelCache } from '../src/ai/client';

/**
 * End-to-end triage, with the model API replaced at the HTTP layer rather than
 * the module layer.
 *
 * Stubbing `fetch` rather than the SDK means the request is really serialised
 * and the response is really parsed, so these tests can assert on the bytes
 * that would leave the process. For a component whose contract includes "never
 * sends a credential", being able to check the actual payload is the point.
 */

const VULNERABLE = [
  'import { db } from "./db";',
  '',
  'const API_KEY = "AKIAIOSFODNN7EXAMPLE";',
  '',
  'export async function getInvoice(req, res) {',
  '  const id = req.params.id;',
  '  const rows = await db.query(`SELECT * FROM invoices WHERE id = ${id}`);',
  '  res.json(rows);',
  '}',
].join('\n');

const PATCH = [
  '@@ -0,0 +1,9 @@',
  ...VULNERABLE.split('\n').map((line) => `+${line}`),
].join('\n');

const FILE: PullRequestFile = {
  filename: 'src/invoices.ts',
  status: 'added',
  additions: 9,
  deletions: 0,
  patch: PATCH,
  sha: 'f'.repeat(40),
};

const INFO: PullRequestInfo = {
  number: 11,
  title: 'Add invoice lookup',
  headSha: 'a'.repeat(40),
  baseSha: 'b'.repeat(40),
  author: 'ansh',
  draft: false,
  changedFiles: 1,
};

class StubGitHub {
  comments: string[] = [];
  statuses: { state: string; description: string }[] = [];

  async pullRequest(): Promise<PullRequestInfo> {
    return INFO;
  }
  async pullRequestFiles(): Promise<PullRequestFile[]> {
    return [FILE];
  }
  async fileContent(): Promise<string | null> {
    return VULNERABLE;
  }
  async upsertComment(
    _o: string,
    _r: string,
    _n: number,
    _m: string,
    body: string,
  ): Promise<{ id: number; updated: boolean }> {
    this.comments.push(body);
    return { id: 1, updated: false };
  }
  async setCommitStatus(
    _o: string,
    _r: string,
    _s: string,
    state: 'success' | 'failure' | 'pending' | 'error',
    description: string,
  ): Promise<void> {
    this.statuses.push({ state, description });
  }
}

interface Capture {
  bodies: Record<string, unknown>[];
  authHeaders: (string | null)[];
}

/**
 * A transport that answers the Messages API with a verdict for every finding it
 * was asked about, so the response always matches the request.
 */
function transportFor(
  verdict: (fingerprint: string, index: number) => Record<string, unknown>,
  capture: Capture,
): typeof globalThis.fetch {
  return (async (url: unknown, init: unknown) => {
    const request = init as { body?: string; headers?: Record<string, string> };
    const body = JSON.parse(String(request.body ?? '{}')) as Record<string, unknown>;
    capture.bodies.push(body);
    const headers = new Headers((request.headers ?? {}) as Record<string, string>);
    capture.authHeaders.push(headers.get('x-api-key'));

    const prompt = String(
      (body.messages as { content: string }[] | undefined)?.[0]?.content ?? '',
    );
    const fingerprints = [...prompt.matchAll(/fingerprint: (\S+)/g)].map((match) => match[1]!);

    return new Response(
      JSON.stringify({
        id: 'msg_test',
        type: 'message',
        role: 'assistant',
        model: String(body.model ?? 'test-model'),
        content: [
          {
            type: 'tool_use',
            id: 'tu_1',
            name: 'report_triage',
            input: { findings: fingerprints.map((fingerprint, index) => verdict(fingerprint, index)) },
          },
        ],
        stop_reason: 'tool_use',
        usage: { input_tokens: 100, output_tokens: 50 },
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  }) as unknown as typeof globalThis.fetch;
}

function config(overrides: Partial<AppConfig['ai']> = {}): AppConfig {
  const base = loadConfig();
  return {
    ...base,
    publicUrl: '',
    github: { ...base.github, token: 'gh', webhookSecret: 'wh' },
    storage: { databasePath: ':memory:' },
    ai: {
      ...base.ai,
      enabled: true,
      apiKey: 'test-key',
      model: 'test-model',
      minSeverity: 'medium',
      maxFindings: 25,
      contextLines: 4,
      maxLinesPerFile: 200,
      effort: 'high',
      maxTokens: 4000,
      timeoutMs: 5000,
      maxRetries: 0,
      dropRefuted: false,
      ...overrides,
    },
  };
}

let store: ReviewStore;

beforeEach(() => {
  store = new ReviewStore(':memory:');
  clearModelCache();
});

describe('triage over the real request path', () => {
  it('sends an excerpt with no credential in it', async () => {
    const capture: Capture = { bodies: [], authHeaders: [] };
    const github = new StubGitHub();
    await new PullRequestReviewer(
      github as unknown as GitHubClient,
      store,
      config({
        fetch: transportFor((fingerprint) => ({
          fingerprint,
          verdict: 'confirmed',
          reasoning: 'The identifier from line 6 reaches the statement on line 7 unbound.',
          fix: 'Pass id as a bound parameter to db.query.',
          confidence: 'high',
        }), capture),
      }),
    ).review({ owner: 'acme', repo: 'app', pullNumber: 11 });

    expect(capture.bodies.length).toBeGreaterThan(0);
    const payload = JSON.stringify(capture.bodies);
    // The vulnerable line must be there - the model cannot judge without it.
    expect(payload).toContain('SELECT * FROM invoices');
    // The AWS key sits four lines above it and must not be.
    expect(payload).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(payload).toContain('[redacted]');
  });

  it('authenticates with the configured key and nothing else', async () => {
    const capture: Capture = { bodies: [], authHeaders: [] };
    await new PullRequestReviewer(
      new StubGitHub() as unknown as GitHubClient,
      store,
      config({
        fetch: transportFor((fingerprint) => ({
          fingerprint,
          verdict: 'confirmed',
          reasoning: 'Reachable.',
          confidence: 'high',
        }), capture),
      }),
    ).review({ owner: 'acme', repo: 'app', pullNumber: 11 });
    expect(capture.authHeaders).toContain('test-key');
  });

  it('replaces the generic explanation with the reviewed one', async () => {
    const capture: Capture = { bodies: [], authHeaders: [] };
    const github = new StubGitHub();
    await new PullRequestReviewer(
      github as unknown as GitHubClient,
      store,
      config({
        fetch: transportFor((fingerprint) => ({
          fingerprint,
          verdict: 'confirmed',
          reasoning: 'The identifier from line 6 reaches the statement on line 7 unbound.',
          fix: 'Pass id as a bound parameter to db.query.',
          confidence: 'high',
        }), capture),
      }),
    ).review({ owner: 'acme', repo: 'app', pullNumber: 11 });

    const comment = github.comments[0]!;
    expect(comment).toContain('The identifier from line 6 reaches the statement on line 7 unbound.');
    expect(comment).toContain('Pass id as a bound parameter to db.query.');
    expect(comment).toContain('Confirmed on review');
    // The rule's general text is still reachable, just demoted.
    expect(comment).toContain('What the rule says in general');
  });

  it('moves a refuted finding out of the blocking set but keeps it visible', async () => {
    const capture: Capture = { bodies: [], authHeaders: [] };
    const github = new StubGitHub();
    const outcome = await new PullRequestReviewer(
      github as unknown as GitHubClient,
      store,
      config({
        fetch: transportFor((fingerprint) => ({
          fingerprint,
          verdict: 'refuted',
          reasoning: 'The identifier is validated against a numeric allow-list before line 7.',
          confidence: 'high',
        }), capture),
      }),
    ).review({ owner: 'acme', repo: 'app', pullNumber: 11 });

    const comment = github.comments[0]!;
    expect(comment).toContain('judged a false positive on review');
    expect(comment).toContain('validated against a numeric allow-list');
    expect(outcome.refuted).toBeGreaterThan(0);
    // The AWS key is never sent for triage, so it still blocks.
    const blockingStatus = github.statuses[github.statuses.length - 1]!;
    expect(blockingStatus.state).toBe('failure');
  });

  it('drops refuted findings entirely when the operator opts in', async () => {
    const capture: Capture = { bodies: [], authHeaders: [] };
    const github = new StubGitHub();
    const outcome = await new PullRequestReviewer(
      github as unknown as GitHubClient,
      store,
      config({
        dropRefuted: true,
        fetch: transportFor((fingerprint) => ({
          fingerprint,
          verdict: 'refuted',
          reasoning: 'Not reachable.',
          confidence: 'high',
        }), capture),
      }),
    ).review({ owner: 'acme', repo: 'app', pullNumber: 11 });

    expect(github.comments[0]!).not.toContain('judged a false positive on review');
    expect(outcome.findings.some((finding) => finding.triage?.verdict === 'refuted')).toBe(false);
  });

  it('keeps the review working when the model API fails', async () => {
    const github = new StubGitHub();
    const failing = (async () =>
      new Response(JSON.stringify({ type: 'error', error: { type: 'api_error', message: 'upstream exploded' } }), {
        status: 500,
        headers: { 'content-type': 'application/json' },
      })) as unknown as typeof globalThis.fetch;

    const outcome = await new PullRequestReviewer(
      github as unknown as GitHubClient,
      store,
      config({ fetch: failing }),
    ).review({ owner: 'acme', repo: 'app', pullNumber: 11 });

    // The deterministic findings survive untouched.
    expect(outcome.findings.length).toBeGreaterThan(0);
    expect(outcome.findings.every((finding) => finding.triage === undefined)).toBe(true);
    const comment = github.comments[0]!;
    expect(comment).toContain('SQL query built by string interpolation');
    // And the comment says the pass did not run, rather than pretending.
    expect(comment).toContain('review pass unavailable');
  });

  it('keeps the review working when the model returns nonsense', async () => {
    const github = new StubGitHub();
    const nonsense = (async () =>
      new Response(
        JSON.stringify({
          id: 'msg_x',
          type: 'message',
          role: 'assistant',
          model: 'test-model',
          content: [{ type: 'text', text: 'I would rather not.' }],
          stop_reason: 'end_turn',
          usage: { input_tokens: 1, output_tokens: 1 },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      )) as unknown as typeof globalThis.fetch;

    const outcome = await new PullRequestReviewer(
      github as unknown as GitHubClient,
      store,
      config({ fetch: nonsense }),
    ).review({ owner: 'acme', repo: 'app', pullNumber: 11 });

    expect(outcome.findings.length).toBeGreaterThan(0);
    expect(outcome.findings.every((finding) => finding.triage === undefined)).toBe(true);
    expect(github.comments[0]!).toContain('SQL query built by string interpolation');
  });

  it('does not call the model at all when triage is disabled', async () => {
    let called = false;
    const spy = (async () => {
      called = true;
      throw new Error('should not be called');
    }) as unknown as typeof globalThis.fetch;

    const github = new StubGitHub();
    await new PullRequestReviewer(
      github as unknown as GitHubClient,
      store,
      config({ enabled: false, fetch: spy }),
    ).review({ owner: 'acme', repo: 'app', pullNumber: 11 });

    expect(called).toBe(false);
    expect(github.comments[0]!).not.toContain('reviewed');
  });

  it('caps a severity adjustment at one step even if the model asks for more', async () => {
    const capture: Capture = { bodies: [], authHeaders: [] };
    const outcome = await new PullRequestReviewer(
      new StubGitHub() as unknown as GitHubClient,
      store,
      config({
        fetch: transportFor((fingerprint) => ({
          fingerprint,
          verdict: 'likely',
          reasoning: 'Only reachable from an internal admin route.',
          severity: 'info',
          confidence: 'high',
        }), capture),
      }),
    ).review({ owner: 'acme', repo: 'app', pullNumber: 11 });

    const sql = outcome.findings.find((finding) => finding.category === 'sql-injection')!;
    // Critical may become high, and no further.
    expect(sql.severity).toBe('high');
    expect(sql.triage?.severityChangedFrom).toBe('critical');
  });

  it('records the reviewed severity in the store, so trends reflect it', async () => {
    const capture: Capture = { bodies: [], authHeaders: [] };
    await new PullRequestReviewer(
      new StubGitHub() as unknown as GitHubClient,
      store,
      config({
        fetch: transportFor((fingerprint) => ({
          fingerprint,
          verdict: 'likely',
          reasoning: 'Reachable only with admin credentials.',
          severity: 'high',
          confidence: 'high',
        }), capture),
      }),
    ).review({ owner: 'acme', repo: 'app', pullNumber: 11 });

    const rows = store.connection
      .prepare<[], { severity: string; rule_id: string }>(
        'SELECT severity, rule_id FROM finding_state ORDER BY rule_id',
      )
      .all();
    const sql = rows.find((row) => row.rule_id.startsWith('sql-injection'))!;
    expect(sql.severity).toBe('high');
  });
});
