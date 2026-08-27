import type { Advisory, Ecosystem } from './advisories';
import { logger } from '../util/logger';

/**
 * Live advisory data from OSV.
 *
 * The bundled snapshot in `advisories.ts` is a floor: it covers the packages
 * that actually show up in dependency bumps and nothing else. A security tool
 * that tells you a dependency is fine when a published advisory says otherwise
 * is worse than one that says nothing, so this queries OSV for the versions a
 * pull request actually declares.
 *
 * Two design choices are worth stating.
 *
 * The query includes the version, which means OSV decides whether that version
 * is affected. There is no version-range arithmetic here at all - a returned
 * vulnerability *is* the answer. Reimplementing per-ecosystem range semantics
 * (npm's semver, Maven's ordering, Go's pseudo-versions) would be a large
 * surface for subtle wrongness, and being subtly wrong about "is this version
 * affected" is the one thing this component must not be.
 *
 * Failure is silent and total. Any error, timeout or malformed response falls
 * back to the bundled snapshot: an unreachable third-party service must never
 * turn a working review into a failed one, and must never make a review report
 * *fewer* problems than it would have offline.
 */

/** OSV's ecosystem names differ from ours. */
const ECOSYSTEM_NAMES: Record<Ecosystem, string> = {
  npm: 'npm',
  pypi: 'PyPI',
  maven: 'Maven',
  go: 'Go',
  rubygems: 'RubyGems',
  composer: 'Packagist',
};

export interface OsvQuery {
  ecosystem: Ecosystem;
  name: string;
  /** A concrete version, not a range. */
  version: string;
}

export interface OsvOptions {
  baseUrl: string;
  timeoutMs: number;
  /** Cap on detail lookups per review, so a bad day cannot become a slow one. */
  maxDetailLookups: number;
  /** How long a result stays cached, in milliseconds. */
  cacheTtlMs: number;
  fetch?: typeof globalThis.fetch;
}

export const DEFAULT_OSV_OPTIONS: OsvOptions = {
  baseUrl: 'https://api.osv.dev',
  timeoutMs: 8_000,
  maxDetailLookups: 40,
  cacheTtlMs: 6 * 60 * 60 * 1000,
};

/** Key of the advisory index the dependency rule consults. */
export function advisoryKey(ecosystem: Ecosystem, name: string): string {
  return `${ecosystem}:${name.toLowerCase()}`;
}

export type AdvisoryIndex = Map<string, Advisory[]>;

interface CacheEntry {
  advisories: Advisory[];
  expiresAt: number;
}

/**
 * Process-lifetime cache keyed by the exact query.
 *
 * A monorepo pull request can declare the same dependency in a dozen manifests,
 * and consecutive pushes re-ask the same questions. Advisories change on the
 * order of days, so a few hours of staleness is a good trade for not hammering
 * a free public service.
 */
const cache = new Map<string, CacheEntry>();

export function clearOsvCache(): void {
  cache.clear();
}

interface BatchResponse {
  results?: { vulns?: { id?: string }[] }[];
}

interface VulnDetail {
  id?: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: { type?: string; score?: string }[];
  database_specific?: { severity?: string; cwe_ids?: string[] };
  affected?: {
    package?: { ecosystem?: string; name?: string };
    ranges?: { events?: { introduced?: string; fixed?: string }[] }[];
  }[];
}

export interface LookupResult {
  index: AdvisoryIndex;
  /** How many queries were answered from cache. */
  cached: number;
  /** How many advisories were found. */
  found: number;
  /** Set when the lookup could not complete; the caller falls back. */
  error?: string;
  durationMs: number;
}

/**
 * Looks up advisories for a set of declared dependencies.
 *
 * Never throws. The returned index is merged with the bundled snapshot by the
 * caller rather than replacing it, so a partial answer still adds information.
 */
export async function lookupAdvisories(
  queries: readonly OsvQuery[],
  options: OsvOptions = DEFAULT_OSV_OPTIONS,
): Promise<LookupResult> {
  const started = Date.now();
  const index: AdvisoryIndex = new Map();

  const deduped = dedupe(queries);
  if (deduped.length === 0) {
    return { index, cached: 0, found: 0, durationMs: 0 };
  }

  // Serve what we can from cache before asking anyone anything.
  const pending: OsvQuery[] = [];
  let cached = 0;
  const now = Date.now();
  for (const query of deduped) {
    const entry = cache.get(cacheKey(query));
    if (entry && entry.expiresAt > now) {
      cached += 1;
      if (entry.advisories.length > 0) {
        addAll(index, query, entry.advisories);
      }
      continue;
    }
    pending.push(query);
  }

  if (pending.length === 0) {
    return { index, cached, found: countAdvisories(index), durationMs: Date.now() - started };
  }

  const doFetch = options.fetch ?? globalThis.fetch;

  try {
    const batch = await request<BatchResponse>(
      doFetch,
      `${options.baseUrl}/v1/querybatch`,
      {
        queries: pending.map((query) => ({
          package: { name: query.name, ecosystem: ECOSYSTEM_NAMES[query.ecosystem] },
          version: query.version,
        })),
      },
      options.timeoutMs,
    );

    // OSV answers positionally, so a length mismatch means the response does
    // not describe the questions we asked and cannot be trusted.
    const results = batch.results ?? [];
    if (results.length !== pending.length) {
      throw new Error(
        `OSV returned ${results.length} results for ${pending.length} queries`,
      );
    }

    // Collect the vulnerability ids we need details for, deduplicated: one
    // advisory commonly affects several packages in the same pull request.
    const idsByQuery = new Map<string, string[]>();
    const allIds = new Set<string>();
    results.forEach((result, position) => {
      const query = pending[position]!;
      const ids = (result.vulns ?? [])
        .map((vuln) => vuln.id)
        .filter((id): id is string => typeof id === 'string');
      idsByQuery.set(cacheKey(query), ids);
      for (const id of ids) allIds.add(id);
    });

    const details = await fetchDetails(doFetch, [...allIds], options);

    for (const query of pending) {
      const ids = idsByQuery.get(cacheKey(query)) ?? [];
      const advisories = ids
        .map((id) => details.get(id))
        .filter((detail): detail is VulnDetail => detail !== undefined)
        .map((detail) => toAdvisory(detail, query));
      cache.set(cacheKey(query), {
        advisories,
        expiresAt: Date.now() + options.cacheTtlMs,
      });
      if (advisories.length > 0) addAll(index, query, advisories);
    }

    const found = countAdvisories(index);
    logger.info('osv lookup complete', {
      queried: pending.length,
      cached,
      found,
      detailLookups: details.size,
      durationMs: Date.now() - started,
    });
    return { index, cached, found, durationMs: Date.now() - started };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.warn('osv lookup failed, falling back to the bundled snapshot', { error: message });
    // Return whatever the cache already gave us. Partial is better than none,
    // and none is still safe because the bundled snapshot always applies.
    return { index, cached, found: countAdvisories(index), error: message, durationMs: Date.now() - started };
  }
}

async function fetchDetails(
  doFetch: typeof globalThis.fetch,
  ids: readonly string[],
  options: OsvOptions,
): Promise<Map<string, VulnDetail>> {
  const out = new Map<string, VulnDetail>();
  const wanted = ids.slice(0, options.maxDetailLookups);

  // Bounded concurrency: enough to be quick, not enough to look like abuse of a
  // free public service.
  const concurrency = Math.min(6, wanted.length);
  let cursor = 0;

  async function worker(): Promise<void> {
    while (cursor < wanted.length) {
      const id = wanted[cursor];
      cursor += 1;
      if (!id) return;
      try {
        const detail = await request<VulnDetail>(
          doFetch,
          `${options.baseUrl}/v1/vulns/${encodeURIComponent(id)}`,
          null,
          options.timeoutMs,
        );
        out.set(id, detail);
      } catch (error) {
        // One unavailable advisory should not lose the rest.
        logger.debug('osv detail lookup failed', { id, error: (error as Error).message });
      }
    }
  }

  await Promise.all(Array.from({ length: concurrency }, () => worker()));
  return out;
}

async function request<T>(
  doFetch: typeof globalThis.fetch,
  url: string,
  body: unknown,
  timeoutMs: number,
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await doFetch(url, {
      method: body === null ? 'GET' : 'POST',
      headers: {
        accept: 'application/json',
        ...(body === null ? {} : { 'content-type': 'application/json' }),
      },
      ...(body === null ? {} : { body: JSON.stringify(body) }),
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(`${url} responded ${response.status}`);
    }
    return (await response.json()) as T;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Maps an OSV record onto our advisory shape.
 *
 * Severity comes from the ecosystem database's own rating where there is one,
 * and from the CVSS vector otherwise. Falling back to a middling default rather
 * than to `low` matters: an advisory with no rating is unrated, not harmless.
 */
export function toAdvisory(detail: VulnDetail, query: OsvQuery): Advisory {
  const cve = (detail.aliases ?? []).find((alias) => alias.startsWith('CVE-')) ?? detail.id ?? 'unknown';
  const fixedIn = findFixedVersion(detail, query) ?? 'a later version';

  return {
    ecosystem: query.ecosystem,
    name: query.name,
    fixedIn,
    cve,
    severity: severityFrom(detail),
    summary: (detail.summary ?? detail.details ?? 'No summary published.').split('\n')[0]!.trim(),
  };
}

function severityFrom(detail: VulnDetail): Advisory['severity'] {
  const rated = detail.database_specific?.severity?.toUpperCase();
  if (rated === 'CRITICAL') return 'critical';
  if (rated === 'HIGH') return 'high';
  if (rated === 'MODERATE' || rated === 'MEDIUM') return 'medium';
  if (rated === 'LOW') return 'low';

  const vector = detail.severity?.find((entry) => entry.type?.startsWith('CVSS'))?.score;
  const score = vector ? cvssBaseScore(vector) : null;
  if (score !== null) {
    if (score >= 9) return 'critical';
    if (score >= 7) return 'high';
    if (score >= 4) return 'medium';
    return 'low';
  }
  // Unrated is not harmless.
  return 'medium';
}

/**
 * Reads a numeric base score when the vector carries one.
 *
 * A full CVSS calculation is not attempted: a wrong score is worse than no
 * score, and the ecosystem rating above covers the overwhelming majority of
 * records. This only picks up the numeric form some databases publish.
 */
function cvssBaseScore(vector: string): number | null {
  const numeric = /^\d+(?:\.\d+)?$/.exec(vector.trim());
  if (numeric) return Number(numeric[0]);
  return null;
}

function findFixedVersion(detail: VulnDetail, query: OsvQuery): string | null {
  const osvEcosystem = ECOSYSTEM_NAMES[query.ecosystem];
  const lowerName = query.name.toLowerCase();
  for (const affected of detail.affected ?? []) {
    if (affected.package?.ecosystem !== osvEcosystem) continue;
    if ((affected.package?.name ?? '').toLowerCase() !== lowerName) continue;
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) return event.fixed;
      }
    }
  }
  return null;
}

function dedupe(queries: readonly OsvQuery[]): OsvQuery[] {
  const seen = new Set<string>();
  const out: OsvQuery[] = [];
  for (const query of queries) {
    if (!query.name || !query.version) continue;
    const key = cacheKey(query);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(query);
  }
  return out;
}

function cacheKey(query: OsvQuery): string {
  return `${query.ecosystem}:${query.name.toLowerCase()}@${query.version}`;
}

function addAll(index: AdvisoryIndex, query: OsvQuery, advisories: Advisory[]): void {
  const key = advisoryKey(query.ecosystem, query.name);
  const existing = index.get(key) ?? [];
  index.set(key, [...existing, ...advisories]);
}

function countAdvisories(index: AdvisoryIndex): number {
  let total = 0;
  for (const advisories of index.values()) total += advisories.length;
  return total;
}
