import type { AddressInfo } from 'node:net';
import { createHmac } from 'node:crypto';
import type { Server } from 'node:http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config';
import { createServer } from '../src/server';
import type { ReviewStore } from '../src/storage/database';

/**
 * Route-level tests over a real listening server, so the raw-body handling and
 * middleware ordering are exercised exactly as they run in production. The
 * GitHub token is a placeholder: every test here stops before a network call.
 */

const SECRET = 'test-webhook-secret';

let server: Server;
let store: ReviewStore;
let baseUrl: string;

beforeAll(async () => {
  const base = loadConfig();
  const parts = createServer({
    ...base,
    port: 0,
    publicUrl: '',
    github: { ...base.github, token: 'placeholder', webhookSecret: SECRET },
    storage: { databasePath: ':memory:' },
  });
  store = parts.store;
  await new Promise<void>((resolve) => {
    server = parts.app.listen(0, resolve);
  });
  const address = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${address.port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  store.close();
});

function sign(body: string): string {
  return `sha256=${createHmac('sha256', SECRET).update(Buffer.from(body)).digest('hex')}`;
}

async function post(path: string, body: string, headers: Record<string, string> = {}) {
  return fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body,
  });
}

describe('dashboard routes', () => {
  it('serves the dashboard as HTML', async () => {
    const response = await fetch(`${baseUrl}/`);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const html = await response.text();
    expect(html).toContain('Security review');
    expect(html).toContain('No reviews yet');
  });

  it('sends hardening headers', async () => {
    const response = await fetch(`${baseUrl}/`);
    expect(response.headers.get('content-security-policy')).toContain("default-src 'none'");
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    expect(response.headers.get('x-frame-options')).toBe('DENY');
    expect(response.headers.get('referrer-policy')).toBe('no-referrer');
    expect(response.headers.get('x-powered-by')).toBeNull();
  });

  it('falls back to the default window for an unsupported value', async () => {
    const response = await fetch(`${baseUrl}/api/stats?days=99999`);
    const body = (await response.json()) as { filter: { days: number } };
    expect(body.filter.days).toBe(30);
  });

  it('accepts an allowed window', async () => {
    const response = await fetch(`${baseUrl}/api/stats?days=90`);
    const body = (await response.json()) as { filter: { days: number } };
    expect(body.filter.days).toBe(90);
  });

  it('exposes the stats API', async () => {
    const response = await fetch(`${baseUrl}/api/stats`);
    expect(response.status).toBe(200);
    const body = (await response.json()) as { overview: { totalOpen: number } };
    expect(body.overview.totalOpen).toBe(0);
  });

  it('exposes findings and scans', async () => {
    expect((await fetch(`${baseUrl}/api/findings`)).status).toBe(200);
    expect((await fetch(`${baseUrl}/api/scans`)).status).toBe(200);
  });

  it('answers a health check', async () => {
    const body = (await (await fetch(`${baseUrl}/healthz`)).json()) as { status: string };
    expect(body.status).toBe('ok');
  });

  it('returns 404 for an unknown route', async () => {
    expect((await fetch(`${baseUrl}/nope`)).status).toBe(404);
  });
});

describe('webhook route', () => {
  const payload = JSON.stringify({
    action: 'labeled',
    pull_request: { number: 1, draft: false, head: { sha: 'abc' } },
    repository: { name: 'app', owner: { login: 'acme' } },
  });

  it('rejects an unsigned delivery', async () => {
    const response = await post('/webhook', payload, { 'x-github-event': 'pull_request' });
    expect(response.status).toBe(401);
  });

  it('rejects a delivery signed with the wrong secret', async () => {
    const wrong = `sha256=${createHmac('sha256', 'nope').update(Buffer.from(payload)).digest('hex')}`;
    const response = await post('/webhook', payload, {
      'x-github-event': 'pull_request',
      'x-hub-signature-256': wrong,
    });
    expect(response.status).toBe(401);
  });

  it('gives the same opaque error for every rejection reason', async () => {
    const unsigned = await post('/webhook', payload, { 'x-github-event': 'pull_request' });
    const wrong = await post('/webhook', payload, {
      'x-github-event': 'pull_request',
      'x-hub-signature-256': 'sha256=deadbeef',
    });
    expect(await unsigned.json()).toEqual(await wrong.json());
  });

  it('answers a signed ping', async () => {
    const body = JSON.stringify({ zen: 'Keep it logically awesome.' });
    const response = await post('/webhook', body, {
      'x-github-event': 'ping',
      'x-hub-signature-256': sign(body),
    });
    expect(response.status).toBe(200);
  });

  it('acknowledges an event it does not act on', async () => {
    const response = await post('/webhook', payload, {
      'x-github-event': 'pull_request',
      'x-hub-signature-256': sign(payload),
    });
    expect(response.status).toBe(202);
    const body = (await response.json()) as { ignored: string };
    expect(body.ignored).toContain('labeled');
  });

  it('rejects a signed body that is not JSON', async () => {
    const body = 'not json';
    const response = await post('/webhook', body, {
      'x-github-event': 'pull_request',
      'x-hub-signature-256': sign(body),
    });
    expect(response.status).toBe(400);
  });

  it('acknowledges a reviewable event before doing the work', async () => {
    const reviewable = JSON.stringify({
      action: 'opened',
      pull_request: { number: 3, draft: false, head: { sha: 'abc' } },
      repository: { name: 'app', owner: { login: 'acme' } },
    });
    const response = await post('/webhook', reviewable, {
      'x-github-event': 'pull_request',
      'x-hub-signature-256': sign(reviewable),
    });
    // 202 comes back immediately; the review runs out of band and its GitHub
    // calls fail against the placeholder token, which must not affect this.
    expect(response.status).toBe(202);
    const body = (await response.json()) as { accepted: { pullNumber: number } };
    expect(body.accepted.pullNumber).toBe(3);
  });
});

describe('manual review route', () => {
  it('requires the shared token', async () => {
    const response = await post('/api/review', JSON.stringify({ owner: 'a', repo: 'b', pullNumber: 1 }));
    expect(response.status).toBe(401);
  });

  it('validates the body once authorised', async () => {
    const response = await post('/api/review', JSON.stringify({ owner: 'a' }), {
      'x-review-token': SECRET,
    });
    expect(response.status).toBe(400);
  });

  it('accepts a complete authorised request', async () => {
    const response = await post(
      '/api/review',
      JSON.stringify({ owner: 'acme', repo: 'app', pullNumber: 9 }),
      { 'x-review-token': SECRET },
    );
    expect(response.status).toBe(202);
  });
});
