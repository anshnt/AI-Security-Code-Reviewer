import { createHmac, timingSafeEqual } from 'node:crypto';

/**
 * Webhook authentication and event routing.
 *
 * This endpoint is the one piece of the system exposed to the internet, so it
 * gets the strictest treatment in the codebase: the signature is verified
 * against the raw bytes before the payload is parsed at all, and the comparison
 * is constant-time. Parsing first and verifying later would mean running a JSON
 * parser on unauthenticated input and, worse, tempting future code into
 * trusting fields from an unverified body.
 */

export type SignatureResult =
  | { ok: true }
  | { ok: false; reason: 'missing-secret' | 'missing-signature' | 'malformed-signature' | 'mismatch' };

/**
 * Verifies the `X-Hub-Signature-256` header against the raw request body.
 * `rawBody` must be the exact bytes GitHub sent - re-serialising a parsed
 * object changes key order and whitespace and will never match.
 */
export function verifySignature(
  rawBody: Buffer,
  signatureHeader: string | undefined,
  secret: string,
): SignatureResult {
  if (!secret) return { ok: false, reason: 'missing-secret' };
  if (!signatureHeader) return { ok: false, reason: 'missing-signature' };
  if (!signatureHeader.startsWith('sha256=')) return { ok: false, reason: 'malformed-signature' };

  const expected = `sha256=${createHmac('sha256', secret).update(rawBody).digest('hex')}`;
  const provided = Buffer.from(signatureHeader, 'utf8');
  const computed = Buffer.from(expected, 'utf8');
  // timingSafeEqual throws on a length mismatch, so check length first - the
  // length of a signature is not a secret.
  if (provided.length !== computed.length) return { ok: false, reason: 'mismatch' };
  return timingSafeEqual(provided, computed) ? { ok: true } : { ok: false, reason: 'mismatch' };
}

export interface PullRequestEvent {
  kind: 'pull_request';
  owner: string;
  repo: string;
  pullNumber: number;
  action: string;
  headSha: string;
  draft: boolean;
}

export type ParsedEvent =
  | PullRequestEvent
  | { kind: 'ping' }
  | { kind: 'ignored'; reason: string };

/** Actions that mean "there is new code to look at". */
const REVIEWABLE_ACTIONS = new Set(['opened', 'reopened', 'synchronize', 'ready_for_review']);

/**
 * Interprets a verified payload. Returns `ignored` rather than throwing for
 * events we do not act on, because GitHub delivers many event types to a single
 * endpoint and a non-2xx response would put the hook into a failing state.
 */
export function parseEvent(eventName: string | undefined, payload: unknown): ParsedEvent {
  if (eventName === 'ping') return { kind: 'ping' };
  if (eventName !== 'pull_request') {
    return { kind: 'ignored', reason: `unhandled event type: ${eventName ?? 'unknown'}` };
  }

  const body = payload as {
    action?: string;
    number?: number;
    pull_request?: { number?: number; draft?: boolean; head?: { sha?: string } };
    repository?: { name?: string; owner?: { login?: string } };
  };

  const action = body.action ?? '';
  if (!REVIEWABLE_ACTIONS.has(action)) {
    return { kind: 'ignored', reason: `pull_request action not reviewable: ${action}` };
  }

  const owner = body.repository?.owner?.login;
  const repo = body.repository?.name;
  const pullNumber = body.pull_request?.number ?? body.number;
  const headSha = body.pull_request?.head?.sha;

  if (!owner || !repo || !pullNumber || !headSha) {
    return { kind: 'ignored', reason: 'payload missing repository or pull request fields' };
  }

  const draft = Boolean(body.pull_request?.draft);
  // A draft is still worth reviewing once it is marked ready; until then the
  // author is mid-thought and comments are noise.
  if (draft && action !== 'ready_for_review') {
    return { kind: 'ignored', reason: 'pull request is a draft' };
  }

  return { kind: 'pull_request', owner, repo, pullNumber, action, headSha, draft };
}
