import { beforeEach, describe, expect, it } from 'vitest';
import { loadConfig, type AppConfig } from '../src/config';
import type { GitHubClient, PullRequestFile, PullRequestInfo } from '../src/github/client';
import { PullRequestReviewer } from '../src/github/reviewer';
import { ReviewStore } from '../src/storage/database';

/**
 * A stand-in for the REST client. Recording what the reviewer *would* post is
 * the only way to test the interesting behaviour - comment upsert, status
 * transitions, oversized-PR handling - without a network.
 */
class StubClient {
  comments: { body: string; marker: string }[] = [];
  statuses: { state: string; description: string }[] = [];
  commentId = 100;
  existingComment: string | null = null;

  constructor(
    private readonly info: PullRequestInfo,
    private readonly files: PullRequestFile[],
    private readonly contents: Record<string, string | null> = {},
  ) {}

  async pullRequest(): Promise<PullRequestInfo> {
    return this.info;
  }

  async pullRequestFiles(): Promise<PullRequestFile[]> {
    return this.files;
  }

  async fileContent(_o: string, _r: string, path: string): Promise<string | null> {
    return this.contents[path] ?? null;
  }

  async upsertComment(
    _o: string,
    _r: string,
    _n: number,
    marker: string,
    body: string,
  ): Promise<{ id: number; updated: boolean }> {
    const updated = this.existingComment !== null;
    this.existingComment = body;
    this.comments.push({ body, marker });
    return { id: this.commentId, updated };
  }

  async setCommitStatus(
    _o: string,
    _r: string,
    _sha: string,
    state: 'success' | 'failure' | 'pending' | 'error',
    description: string,
  ): Promise<void> {
    this.statuses.push({ state, description });
  }
}

function config(overrides: Partial<AppConfig['review']> = {}): AppConfig {
  const base = loadConfig();
  return {
    ...base,
    publicUrl: 'https://review.example.com',
    github: { ...base.github, token: 't', webhookSecret: 's' },
    storage: { databasePath: ':memory:' },
    review: { ...base.review, ...overrides },
  };
}

const INFO: PullRequestInfo = {
  number: 7,
  title: 'Add user lookup',
  headSha: 'a'.repeat(40),
  baseSha: 'b'.repeat(40),
  author: 'ansh',
  draft: false,
  changedFiles: 1,
};

const VULNERABLE = [
  'export async function getUser(req, res) {',
  '  const id = req.params.id;',
  '  const rows = await db.query(`SELECT * FROM users WHERE id = ${id}`);',
  '  res.json(rows);',
  '}',
].join('\n');

const FIXED = [
  'export async function getUser(req, res) {',
  '  const id = req.params.id;',
  '  const rows = await db.query("SELECT * FROM users WHERE id = ?", [id]);',
  '  res.json(rows);',
  '}',
].join('\n');

const PATCH = [
  '@@ -0,0 +1,5 @@',
  '+export async function getUser(req, res) {',
  '+  const id = req.params.id;',
  '+  const rows = await db.query(`SELECT * FROM users WHERE id = ${id}`);',
  '+  res.json(rows);',
  '+}',
].join('\n');

const FILE: PullRequestFile = {
  filename: 'src/users.ts',
  status: 'added',
  additions: 5,
  deletions: 0,
  patch: PATCH,
  sha: 'f'.repeat(40),
};

describe('PullRequestReviewer', () => {
  let store: ReviewStore;

  beforeEach(() => {
    store = new ReviewStore(':memory:');
  });

  it('finds the vulnerability, comments and fails the status', async () => {
    const client = new StubClient(INFO, [FILE], { 'src/users.ts': VULNERABLE });
    const reviewer = new PullRequestReviewer(client as unknown as GitHubClient, store, config());

    const outcome = await reviewer.review({ owner: 'acme', repo: 'app', pullNumber: 7 });

    expect(outcome.findings.length).toBeGreaterThan(0);
    expect(outcome.findings[0]!.category).toBe('sql-injection');
    expect(outcome.status).toBe('failure');
    expect(outcome.newFindings).toBe(outcome.findings.length);

    expect(client.comments).toHaveLength(1);
    expect(client.comments[0]!.body).toContain('SQL query built by string interpolation');
    expect(client.comments[0]!.body).toContain('src/users.ts:3');

    // Pending first, verdict second - so a long review is visible while it runs.
    expect(client.statuses.map((entry) => entry.state)).toEqual(['pending', 'failure']);
  });

  it('reports success and resolves the finding once the code is fixed', async () => {
    const cfg = config();
    const first = new StubClient(INFO, [FILE], { 'src/users.ts': VULNERABLE });
    await new PullRequestReviewer(first as unknown as GitHubClient, store, cfg).review({
      owner: 'acme',
      repo: 'app',
      pullNumber: 7,
    });

    const fixedFile: PullRequestFile = { ...FILE, status: 'modified' };
    const second = new StubClient(
      { ...INFO, headSha: 'c'.repeat(40) },
      [fixedFile],
      { 'src/users.ts': FIXED },
    );
    const outcome = await new PullRequestReviewer(
      second as unknown as GitHubClient,
      store,
      cfg,
    ).review({ owner: 'acme', repo: 'app', pullNumber: 7 });

    expect(outcome.findings).toEqual([]);
    expect(outcome.status).toBe('success');
    expect(outcome.resolvedFindings).toBe(1);
    expect(second.comments[0]!.body).toContain('no issues found');
    expect(second.comments[0]!.body).toContain('resolved 1 previously reported finding');
  });

  it('does not label a pre-existing finding as new on a second push', async () => {
    const cfg = config();
    await new PullRequestReviewer(
      new StubClient(INFO, [FILE], { 'src/users.ts': VULNERABLE }) as unknown as GitHubClient,
      store,
      cfg,
    ).review({ owner: 'acme', repo: 'app', pullNumber: 7 });

    const again = new StubClient(INFO, [FILE], { 'src/users.ts': VULNERABLE });
    const outcome = await new PullRequestReviewer(
      again as unknown as GitHubClient,
      store,
      cfg,
    ).review({ owner: 'acme', repo: 'app', pullNumber: 7 });

    expect(outcome.newFindings).toBe(0);
    expect(again.comments[0]!.body).not.toContain('introduced by this pull request');
  });

  it('falls back to the patch when the file cannot be fetched', async () => {
    const client = new StubClient(INFO, [FILE], {});
    const outcome = await new PullRequestReviewer(
      client as unknown as GitHubClient,
      store,
      config(),
    ).review({ owner: 'acme', repo: 'app', pullNumber: 7 });
    expect(outcome.findings.length).toBeGreaterThan(0);
  });

  it('restricts reporting to changed lines on a modified file', async () => {
    const modified: PullRequestFile = {
      ...FILE,
      status: 'modified',
      patch: ['@@ -4,1 +4,1 @@', '-  res.json(rows);', '+  res.json({ rows });'].join('\n'),
    };
    const client = new StubClient(INFO, [modified], { 'src/users.ts': VULNERABLE });
    const outcome = await new PullRequestReviewer(
      client as unknown as GitHubClient,
      store,
      config(),
    ).review({ owner: 'acme', repo: 'app', pullNumber: 7 });

    // The injection is on line 3, which this push did not touch.
    expect(outcome.findings).toEqual([]);
    expect(outcome.status).toBe('success');
  });

  it('skips a pull request above the file limit without failing it', async () => {
    const client = new StubClient({ ...INFO, changedFiles: 5000 }, [FILE]);
    const outcome = await new PullRequestReviewer(
      client as unknown as GitHubClient,
      store,
      config({ maxFilesPerPullRequest: 10 }),
    ).review({ owner: 'acme', repo: 'app', pullNumber: 7 });

    expect(outcome.skipped).toContain('above the');
    expect(client.comments).toHaveLength(0);
    expect(client.statuses).toEqual([{ state: 'success', description: 'Skipped: pull request too large to review' }]);
  });

  it('never fails the status when the threshold is disabled', async () => {
    const client = new StubClient(INFO, [FILE], { 'src/users.ts': VULNERABLE });
    const outcome = await new PullRequestReviewer(
      client as unknown as GitHubClient,
      store,
      config({ failOnSeverity: 'never' }),
    ).review({ owner: 'acme', repo: 'app', pullNumber: 7 });

    expect(outcome.findings.length).toBeGreaterThan(0);
    expect(outcome.status).toBe('success');
  });

  it('persists the scan so the dashboard can read it', async () => {
    const client = new StubClient(INFO, [FILE], { 'src/users.ts': VULNERABLE });
    const outcome = await new PullRequestReviewer(
      client as unknown as GitHubClient,
      store,
      config(),
    ).review({ owner: 'acme', repo: 'app', pullNumber: 7 });

    expect(outcome.scanId).toBeGreaterThan(0);
    expect(store.openFingerprints('acme/app').size).toBe(outcome.findings.length);
  });

  it('links the comment footer to the dashboard for this repository', async () => {
    const client = new StubClient(INFO, [FILE], { 'src/users.ts': VULNERABLE });
    await new PullRequestReviewer(client as unknown as GitHubClient, store, config()).review({
      owner: 'acme',
      repo: 'app',
      pullNumber: 7,
    });
    expect(client.comments[0]!.body).toContain('https://review.example.com/?repo=acme%2Fapp');
  });
});
