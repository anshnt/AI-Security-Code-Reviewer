import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parseEvent, verifySignature } from '../src/github/webhook';

const SECRET = 'a-webhook-secret';

function sign(body: string, secret = SECRET): string {
  return `sha256=${createHmac('sha256', secret).update(Buffer.from(body)).digest('hex')}`;
}

describe('verifySignature', () => {
  it('accepts a correct signature', () => {
    const body = '{"action":"opened"}';
    expect(verifySignature(Buffer.from(body), sign(body), SECRET)).toEqual({ ok: true });
  });

  it('rejects a signature made with a different secret', () => {
    const body = '{"action":"opened"}';
    expect(verifySignature(Buffer.from(body), sign(body, 'wrong'), SECRET)).toEqual({
      ok: false,
      reason: 'mismatch',
    });
  });

  it('rejects a body that was altered after signing', () => {
    const signature = sign('{"action":"opened"}');
    const result = verifySignature(Buffer.from('{"action":"closed"}'), signature, SECRET);
    expect(result.ok).toBe(false);
  });

  it('rejects a missing signature header', () => {
    expect(verifySignature(Buffer.from('{}'), undefined, SECRET)).toEqual({
      ok: false,
      reason: 'missing-signature',
    });
  });

  it('rejects an unsupported signature algorithm', () => {
    expect(verifySignature(Buffer.from('{}'), 'sha1=abc', SECRET)).toEqual({
      ok: false,
      reason: 'malformed-signature',
    });
  });

  it('refuses to verify when no secret is configured', () => {
    const body = '{}';
    expect(verifySignature(Buffer.from(body), sign(body), '')).toEqual({
      ok: false,
      reason: 'missing-secret',
    });
  });

  it('rejects a truncated signature without throwing', () => {
    const body = '{}';
    expect(verifySignature(Buffer.from(body), 'sha256=abc', SECRET).ok).toBe(false);
  });

  it('verifies byte-for-byte, not by re-serialising', () => {
    // Same object, different whitespace: only the exact bytes must validate.
    const canonical = '{"a":1}';
    const respaced = '{ "a": 1 }';
    expect(verifySignature(Buffer.from(canonical), sign(canonical), SECRET).ok).toBe(true);
    expect(verifySignature(Buffer.from(respaced), sign(canonical), SECRET).ok).toBe(false);
  });
});

describe('parseEvent', () => {
  const payload = {
    action: 'opened',
    pull_request: { number: 42, draft: false, head: { sha: 'abc123' } },
    repository: { name: 'app', owner: { login: 'acme' } },
  };

  it('recognises a reviewable pull request', () => {
    expect(parseEvent('pull_request', payload)).toEqual({
      kind: 'pull_request',
      owner: 'acme',
      repo: 'app',
      pullNumber: 42,
      action: 'opened',
      headSha: 'abc123',
      draft: false,
    });
  });

  it('accepts synchronize, reopened and ready_for_review', () => {
    for (const action of ['synchronize', 'reopened', 'ready_for_review']) {
      const event = parseEvent('pull_request', { ...payload, action });
      expect(event.kind).toBe('pull_request');
    }
  });

  it('ignores non-reviewable actions', () => {
    const event = parseEvent('pull_request', { ...payload, action: 'labeled' });
    expect(event.kind).toBe('ignored');
  });

  it('ignores drafts until they are marked ready', () => {
    const draft = { ...payload, pull_request: { ...payload.pull_request, draft: true } };
    expect(parseEvent('pull_request', draft).kind).toBe('ignored');
    expect(parseEvent('pull_request', { ...draft, action: 'ready_for_review' }).kind).toBe('pull_request');
  });

  it('answers a ping', () => {
    expect(parseEvent('ping', { zen: 'x' })).toEqual({ kind: 'ping' });
  });

  it('ignores other event types rather than failing', () => {
    expect(parseEvent('push', {}).kind).toBe('ignored');
    expect(parseEvent(undefined, {}).kind).toBe('ignored');
  });

  it('ignores a payload missing required fields', () => {
    expect(parseEvent('pull_request', { action: 'opened' }).kind).toBe('ignored');
    expect(
      parseEvent('pull_request', { action: 'opened', repository: { name: 'app' } }).kind,
    ).toBe('ignored');
  });
});
