import Anthropic from '@anthropic-ai/sdk';
import { logger } from '../util/logger';

/**
 * Model access for the triage pass.
 *
 * Two things are deliberately not hardcoded here.
 *
 * The model identifier comes from configuration. A security tool that pins a
 * model string ships a decision that expires: the pin is wrong the moment a
 * better model exists, and wrong in the expensive direction if the pinned model
 * is retired. `AI_MODEL=auto` resolves the newest model the credential can see,
 * which is the right default for "just give me the best available"; an explicit
 * identifier is the right choice for a reproducible pipeline, and is what we
 * recommend in the docs.
 *
 * The credential comes from the environment and is never logged. If it is
 * absent, triage is simply off - the deterministic analyzers are the product,
 * and the model is an enhancement layered on top. A missing key must never turn
 * a working review into a failed one.
 */

export interface ModelAccess {
  client: Anthropic;
  /** The resolved model identifier actually used for requests. */
  model: string;
}

export class ModelUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ModelUnavailableError';
  }
}

export interface ModelOptions {
  apiKey: string;
  /** A model identifier, or `auto` to resolve the newest available. */
  model: string;
  timeoutMs: number;
  maxRetries: number;
  baseUrl?: string;
  /**
   * Replacement for the HTTP transport. Two real uses: routing through a
   * corporate proxy that needs its own agent or headers, and asserting in tests
   * on exactly what would be sent over the wire - which for a component whose
   * job includes not leaking credentials is worth being able to check.
   */
  fetch?: typeof globalThis.fetch;
}

/**
 * Builds a client and settles on a model. `auto` costs one extra request the
 * first time and is cached for the process lifetime, because the answer does
 * not change often enough to justify asking on every review.
 */
export async function connect(options: ModelOptions): Promise<ModelAccess> {
  if (!options.apiKey) {
    throw new ModelUnavailableError('no API key configured');
  }

  const client = new Anthropic({
    apiKey: options.apiKey,
    timeout: options.timeoutMs,
    maxRetries: options.maxRetries,
    ...(options.baseUrl ? { baseURL: options.baseUrl } : {}),
    ...(options.fetch ? { fetch: options.fetch } : {}),
  });

  const model =
    options.model.toLowerCase() === 'auto' ? await resolveNewestModel(client) : options.model;

  return { client, model };
}

let cachedAutoModel: string | null = null;

async function resolveNewestModel(client: Anthropic): Promise<string> {
  if (cachedAutoModel) return cachedAutoModel;
  try {
    const page = await client.models.list({ limit: 20 });
    const models = page.data ?? [];
    if (models.length === 0) {
      throw new ModelUnavailableError('the models endpoint returned no models for this credential');
    }
    // The listing is newest-first, but sort explicitly rather than trusting it.
    const newest = [...models].sort((a, b) => {
      const left = Date.parse(String(a.created_at ?? '')) || 0;
      const right = Date.parse(String(b.created_at ?? '')) || 0;
      return right - left;
    })[0]!;
    cachedAutoModel = newest.id;
    logger.info('resolved model automatically', { model: newest.id, candidates: models.length });
    return newest.id;
  } catch (error) {
    if (error instanceof ModelUnavailableError) throw error;
    throw new ModelUnavailableError(
      `could not resolve a model automatically: ${describeError(error)}. ` +
        'Set AI_MODEL to an explicit identifier.',
    );
  }
}

/** Reset for tests, so a cached resolution does not leak between cases. */
export function clearModelCache(): void {
  cachedAutoModel = null;
}

/**
 * Human-readable error text with no credential in it. The SDK's typed errors
 * carry a status we can act on; anything else is reported as-is.
 */
export function describeError(error: unknown): string {
  if (error instanceof Anthropic.APIError) {
    return `HTTP ${error.status ?? 'unknown'}: ${error.message}`;
  }
  if (error instanceof Error) return error.message;
  return String(error);
}

/** Whether retrying could plausibly help. */
export function isRetryable(error: unknown): boolean {
  if (error instanceof Anthropic.RateLimitError) return true;
  if (error instanceof Anthropic.APIConnectionError) return true;
  if (error instanceof Anthropic.APIError) {
    const status = error.status ?? 0;
    return status === 408 || status === 409 || status === 429 || status >= 500;
  }
  return false;
}

export { Anthropic };
