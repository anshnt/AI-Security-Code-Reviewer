import express, { type Express, type Request, type Response } from 'express';
import type { AppConfig } from './config';
import { renderDashboard } from './dashboard/page';
import { GitHubClient } from './github/client';
import { PullRequestReviewer } from './github/reviewer';
import { parseEvent, verifySignature } from './github/webhook';
import { ReviewStore } from './storage/database';
import {
  knownRepositories,
  openFindings,
  overview,
  recentScans,
  repositorySummaries,
  topRules,
  trend,
  triageAccuracy,
  type StatsFilter,
} from './storage/queries';
import { logger } from './util/logger';

/**
 * HTTP surface: a webhook receiver, a JSON API and the dashboard.
 *
 * The webhook route is mounted with a raw body parser before any JSON parsing,
 * because the signature must be checked against the exact bytes GitHub sent.
 * Every other route gets ordinary parsing.
 */

const ALLOWED_WINDOWS = new Set([7, 14, 30, 90, 180]);

export interface ServerParts {
  app: Express;
  store: ReviewStore;
}

export function createServer(config: AppConfig): ServerParts {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', true);

  const store = new ReviewStore(config.storage.databasePath);
  const client = new GitHubClient(config.github.token, config.github.apiBaseUrl);
  const reviewer = new PullRequestReviewer(client, store, config);

  app.use((_request, response, next) => {
    // The dashboard is self-contained, so it can afford a strict policy.
    response.setHeader(
      'Content-Security-Policy',
      "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; " +
        "img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    );
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('X-Frame-Options', 'DENY');
    next();
  });

  // --- Webhook ------------------------------------------------------------
  // Raw body, capped: an unbounded body on an unauthenticated endpoint is a
  // free memory-exhaustion primitive.
  app.post(
    '/webhook',
    express.raw({ type: '*/*', limit: '10mb' }),
    (request: Request, response: Response) => {
      const rawBody = Buffer.isBuffer(request.body) ? request.body : Buffer.alloc(0);
      const signature = request.get('x-hub-signature-256');
      const delivery = request.get('x-github-delivery') ?? 'unknown';

      const verified = verifySignature(rawBody, signature, config.github.webhookSecret);
      if (!verified.ok) {
        logger.warn('rejected webhook delivery', { delivery, reason: verified.reason });
        // A single opaque status for every failure mode: telling a caller
        // *why* their signature was rejected is free information for them.
        response.status(401).json({ error: 'signature verification failed' });
        return;
      }

      let payload: unknown;
      try {
        payload = JSON.parse(rawBody.toString('utf8'));
      } catch {
        response.status(400).json({ error: 'payload is not valid JSON' });
        return;
      }

      const event = parseEvent(request.get('x-github-event'), payload);
      if (event.kind === 'ping') {
        response.status(200).json({ ok: true, message: 'webhook reachable' });
        return;
      }
      if (event.kind === 'ignored') {
        logger.debug('ignoring delivery', { delivery, reason: event.reason });
        response.status(202).json({ ok: true, ignored: event.reason });
        return;
      }

      // Acknowledge immediately and review out of band. GitHub times deliveries
      // out after ten seconds, and a full review of a large diff takes longer.
      response.status(202).json({
        ok: true,
        accepted: { repository: `${event.owner}/${event.repo}`, pullNumber: event.pullNumber },
      });

      void reviewer
        .review({ owner: event.owner, repo: event.repo, pullNumber: event.pullNumber })
        .catch((error: unknown) => {
          logger.error('review failed', {
            delivery,
            repository: `${event.owner}/${event.repo}`,
            pullNumber: event.pullNumber,
            error: (error as Error).message,
          });
        });
    },
  );

  app.use(express.json({ limit: '1mb' }));

  // --- Dashboard ----------------------------------------------------------
  app.get('/', (request: Request, response: Response) => {
    const filter = readFilter(request);
    const data = {
      filter: { repository: filter.repository ?? null, days: filter.days },
      repositories: knownRepositories(store),
      overview: overview(store, filter),
      trend: trend(store, filter),
      topRules: topRules(store, filter),
      repositorySummaries: repositorySummaries(store),
      recentScans: recentScans(store, filter),
      openFindings: openFindings(store, filter, 25),
      triage: triageAccuracy(store, filter),
    };
    response.setHeader('Content-Type', 'text/html; charset=utf-8');
    response.setHeader('Cache-Control', 'no-store');
    response.send(renderDashboard(data));
  });

  // --- JSON API -----------------------------------------------------------
  app.get('/api/stats', (request: Request, response: Response) => {
    const filter = readFilter(request);
    response.json({
      filter: { repository: filter.repository ?? null, days: filter.days },
      overview: overview(store, filter),
      trend: trend(store, filter),
      topRules: topRules(store, filter),
      repositories: repositorySummaries(store),
      triage: triageAccuracy(store, filter),
    });
  });

  app.get('/api/findings', (request: Request, response: Response) => {
    const filter = readFilter(request);
    const limit = clamp(Number.parseInt(String(request.query.limit ?? '100'), 10) || 100, 1, 500);
    response.json({ findings: openFindings(store, filter, limit) });
  });

  app.get('/api/scans', (request: Request, response: Response) => {
    const filter = readFilter(request);
    const limit = clamp(Number.parseInt(String(request.query.limit ?? '50'), 10) || 50, 1, 200);
    response.json({ scans: recentScans(store, filter, limit) });
  });

  app.get('/healthz', (_request: Request, response: Response) => {
    response.json({ status: 'ok', uptimeSeconds: Math.round(process.uptime()) });
  });

  /**
   * Manual re-review, for backfilling a repository or retrying a delivery that
   * failed. Guarded by the webhook secret so it is not an open proxy for making
   * the service issue authenticated GitHub requests on a stranger's behalf.
   */
  app.post('/api/review', (request: Request, response: Response) => {
    const provided = request.get('x-review-token') ?? '';
    if (!config.github.webhookSecret || provided !== config.github.webhookSecret) {
      response.status(401).json({ error: 'unauthorized' });
      return;
    }
    const body = request.body as { owner?: string; repo?: string; pullNumber?: number };
    if (!body?.owner || !body?.repo || !body?.pullNumber) {
      response.status(400).json({ error: 'owner, repo and pullNumber are required' });
      return;
    }
    void reviewer
      .review({ owner: body.owner, repo: body.repo, pullNumber: body.pullNumber })
      .then((outcome) => {
        logger.info('manual review complete', { scanId: outcome.scanId, findings: outcome.findings.length });
      })
      .catch((error: unknown) => {
        logger.error('manual review failed', { error: (error as Error).message });
      });
    response.status(202).json({ ok: true });
  });

  app.use((_request: Request, response: Response) => {
    response.status(404).json({ error: 'not found' });
  });

  return { app, store };
}

function readFilter(request: Request): StatsFilter {
  const repository = typeof request.query.repo === 'string' && request.query.repo.trim()
    ? request.query.repo.trim()
    : undefined;
  const requested = Number.parseInt(String(request.query.days ?? '30'), 10);
  const days = ALLOWED_WINDOWS.has(requested) ? requested : 30;
  return repository ? { repository, days } : { days };
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}
