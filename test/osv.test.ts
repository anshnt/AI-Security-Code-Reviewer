import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { collectAdvisoryQueries, scanWithAdvisories } from '../src/analysis/engine';
import {
  advisoryKey,
  clearOsvCache,
  lookupAdvisories,
  toAdvisory,
  type OsvOptions,
  type OsvQuery,
} from '../src/analysis/osv';

/**
 * The OSV client is stubbed at the HTTP layer, so these tests exercise the real
 * request bodies and the real parsing. Two properties matter most and both are
 * about failure: a lookup that goes wrong must never report *fewer* problems
 * than an offline run, and it must never take a review down.
 */

const MANIFEST = JSON.stringify(
  {
    name: 'sample',
    dependencies: { lodash: '4.17.15', express: '^4.21.2' },
    devDependencies: { minimist: '1.2.5' },
  },
  null,
  2,
);

function options(overrides: Partial<OsvOptions> = {}): OsvOptions {
  return {
    baseUrl: 'https://osv.test',
    timeoutMs: 1000,
    maxDetailLookups: 40,
    cacheTtlMs: 60_000,
    ...overrides,
  };
}

interface Recorded {
  urls: string[];
  bodies: unknown[];
}

/** A transport that answers querybatch and the detail endpoint from a table. */
function transport(
  table: Record<string, { ids: string[] }>,
  details: Record<string, unknown>,
  recorded: Recorded,
): typeof globalThis.fetch {
  return (async (url: unknown, init: unknown) => {
    const target = String(url);
    recorded.urls.push(target);
    const request = init as { body?: string };

    if (target.endsWith('/v1/querybatch')) {
      const body = JSON.parse(String(request.body ?? '{}')) as {
        queries: { package: { name: string; ecosystem: string }; version: string }[];
      };
      recorded.bodies.push(body);
      return json({
        results: body.queries.map((query) => ({
          vulns: (table[`${query.package.name}@${query.version}`]?.ids ?? []).map((id) => ({ id })),
        })),
      });
    }

    const id = target.split('/').pop()!;
    if (details[id]) return json(details[id]);
    return new Response('not found', { status: 404 });
  }) as unknown as typeof globalThis.fetch;
}

function json(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

const LODASH_DETAIL = {
  id: 'GHSA-35jh-r3h4-6jhm',
  aliases: ['CVE-2021-23337'],
  summary: 'Command Injection in lodash',
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H' }],
  database_specific: { severity: 'HIGH' },
  affected: [
    {
      package: { ecosystem: 'npm', name: 'lodash' },
      ranges: [{ events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
    },
  ],
};

const LODASH_SECOND = {
  id: 'GHSA-29mw-wpgm-hmr9',
  aliases: ['CVE-2020-28500'],
  summary: 'Regular expression denial of service in lodash',
  database_specific: { severity: 'MODERATE' },
  affected: [
    {
      package: { ecosystem: 'npm', name: 'lodash' },
      ranges: [{ events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
    },
  ],
};

beforeEach(() => {
  clearOsvCache();
});

afterEach(() => {
  clearOsvCache();
});

describe('collectAdvisoryQueries', () => {
  it('finds every declared dependency with a resolvable version', () => {
    const queries = collectAdvisoryQueries([
      { filePath: 'package.json', content: MANIFEST, status: 'modified', changedLines: null },
    ]);
    expect(queries).toEqual(
      expect.arrayContaining([
        { ecosystem: 'npm', name: 'lodash', version: '4.17.15' },
        { ecosystem: 'npm', name: 'express', version: '4.21.2' },
        { ecosystem: 'npm', name: 'minimist', version: '1.2.5' },
      ]),
    );
  });

  it('skips a range with no version to ask about', () => {
    const queries = collectAdvisoryQueries([
      {
        filePath: 'package.json',
        content: '{"dependencies":{"anything":"*","other":"latest"}}',
        status: 'modified',
        changedLines: null,
      },
    ]);
    expect(queries).toEqual([]);
  });

  it('reads a requirements file', () => {
    const queries = collectAdvisoryQueries([
      { filePath: 'requirements.txt', content: 'pyyaml==5.3.1\n', status: 'modified', changedLines: null },
    ]);
    expect(queries).toEqual([{ ecosystem: 'pypi', name: 'pyyaml', version: '5.3.1' }]);
  });

  it('ignores files that are not manifests', () => {
    expect(
      collectAdvisoryQueries([
        { filePath: 'src/app.ts', content: 'const a = 1;', status: 'modified', changedLines: null },
      ]),
    ).toEqual([]);
  });

  it('ignores a removed manifest', () => {
    expect(
      collectAdvisoryQueries([
        { filePath: 'package.json', content: MANIFEST, status: 'removed', changedLines: null },
      ]),
    ).toEqual([]);
  });
});

describe('lookupAdvisories', () => {
  const queries: OsvQuery[] = [
    { ecosystem: 'npm', name: 'lodash', version: '4.17.15' },
    { ecosystem: 'npm', name: 'express', version: '4.21.2' },
  ];

  it('sends the ecosystem name the service expects', () => {
    const recorded: Recorded = { urls: [], bodies: [] };
    return lookupAdvisories(
      [{ ecosystem: 'pypi', name: 'pyyaml', version: '5.3.1' }],
      options({ fetch: transport({}, {}, recorded) }),
    ).then(() => {
      const body = recorded.bodies[0] as { queries: { package: { ecosystem: string } }[] };
      // Ours is `pypi`; theirs is `PyPI`.
      expect(body.queries[0]!.package.ecosystem).toBe('PyPI');
    });
  });

  it('returns an advisory for an affected version', async () => {
    const recorded: Recorded = { urls: [], bodies: [] };
    const result = await lookupAdvisories(
      queries,
      options({
        fetch: transport(
          { 'lodash@4.17.15': { ids: ['GHSA-35jh-r3h4-6jhm'] } },
          { 'GHSA-35jh-r3h4-6jhm': LODASH_DETAIL },
          recorded,
        ),
      }),
    );

    const advisories = result.index.get(advisoryKey('npm', 'lodash'))!;
    expect(advisories).toHaveLength(1);
    expect(advisories[0]).toMatchObject({
      name: 'lodash',
      cve: 'CVE-2021-23337',
      severity: 'high',
      fixedIn: '4.17.21',
    });
    expect(result.index.has(advisoryKey('npm', 'express'))).toBe(false);
  });

  it('returns every advisory affecting one package', async () => {
    const recorded: Recorded = { urls: [], bodies: [] };
    const result = await lookupAdvisories(
      [queries[0]!],
      options({
        fetch: transport(
          { 'lodash@4.17.15': { ids: ['GHSA-35jh-r3h4-6jhm', 'GHSA-29mw-wpgm-hmr9'] } },
          { 'GHSA-35jh-r3h4-6jhm': LODASH_DETAIL, 'GHSA-29mw-wpgm-hmr9': LODASH_SECOND },
          recorded,
        ),
      }),
    );
    expect(result.index.get(advisoryKey('npm', 'lodash'))).toHaveLength(2);
    expect(result.found).toBe(2);
  });

  it('deduplicates identical queries before asking', async () => {
    const recorded: Recorded = { urls: [], bodies: [] };
    await lookupAdvisories(
      [queries[0]!, queries[0]!, queries[0]!],
      options({ fetch: transport({}, {}, recorded) }),
    );
    const body = recorded.bodies[0] as { queries: unknown[] };
    expect(body.queries).toHaveLength(1);
  });

  it('serves a repeat lookup from cache without asking again', async () => {
    const recorded: Recorded = { urls: [], bodies: [] };
    const fetchStub = transport(
      { 'lodash@4.17.15': { ids: ['GHSA-35jh-r3h4-6jhm'] } },
      { 'GHSA-35jh-r3h4-6jhm': LODASH_DETAIL },
      recorded,
    );
    await lookupAdvisories([queries[0]!], options({ fetch: fetchStub }));
    const batches = recorded.urls.filter((url) => url.endsWith('/querybatch')).length;

    const second = await lookupAdvisories([queries[0]!], options({ fetch: fetchStub }));
    expect(recorded.urls.filter((url) => url.endsWith('/querybatch'))).toHaveLength(batches);
    expect(second.cached).toBe(1);
    expect(second.index.get(advisoryKey('npm', 'lodash'))).toHaveLength(1);
  });

  it('caches a negative answer too', async () => {
    const recorded: Recorded = { urls: [], bodies: [] };
    const fetchStub = transport({}, {}, recorded);
    await lookupAdvisories([queries[1]!], options({ fetch: fetchStub }));
    const second = await lookupAdvisories([queries[1]!], options({ fetch: fetchStub }));
    expect(second.cached).toBe(1);
    expect(second.found).toBe(0);
  });

  it('fetches each advisory detail once even when several packages share it', async () => {
    const recorded: Recorded = { urls: [], bodies: [] };
    await lookupAdvisories(
      [
        { ecosystem: 'npm', name: 'a', version: '1.0.0' },
        { ecosystem: 'npm', name: 'b', version: '1.0.0' },
      ],
      options({
        fetch: transport(
          { 'a@1.0.0': { ids: ['SHARED-1'] }, 'b@1.0.0': { ids: ['SHARED-1'] } },
          { 'SHARED-1': { ...LODASH_DETAIL, id: 'SHARED-1' } },
          recorded,
        ),
      }),
    );
    expect(recorded.urls.filter((url) => url.includes('/v1/vulns/'))).toHaveLength(1);
  });

  it('reports an error and returns nothing when the batch call fails', async () => {
    const failing = (async () => new Response('boom', { status: 500 })) as unknown as typeof globalThis.fetch;
    const result = await lookupAdvisories(queries, options({ fetch: failing }));
    expect(result.error).toContain('500');
    expect(result.index.size).toBe(0);
  });

  it('rejects a response that does not answer the questions asked', async () => {
    // A positional response of the wrong length cannot be matched to queries,
    // and guessing would attribute advisories to the wrong package.
    const mismatched = (async () =>
      json({ results: [{ vulns: [] }] })) as unknown as typeof globalThis.fetch;
    const result = await lookupAdvisories(queries, options({ fetch: mismatched }));
    expect(result.error).toContain('1 results for 2 queries');
  });

  it('survives a detail lookup failing, keeping the others', async () => {
    const recorded: Recorded = { urls: [], bodies: [] };
    const result = await lookupAdvisories(
      [queries[0]!],
      options({
        fetch: transport(
          { 'lodash@4.17.15': { ids: ['GHSA-35jh-r3h4-6jhm', 'MISSING-1'] } },
          { 'GHSA-35jh-r3h4-6jhm': LODASH_DETAIL },
          recorded,
        ),
      }),
    );
    expect(result.error).toBeUndefined();
    expect(result.index.get(advisoryKey('npm', 'lodash'))).toHaveLength(1);
  });

  it('survives a timeout', async () => {
    const hanging = (async (_url: unknown, init: unknown) => {
      const signal = (init as { signal?: AbortSignal }).signal!;
      return new Promise<Response>((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(new Error('aborted')));
      });
    }) as unknown as typeof globalThis.fetch;
    const result = await lookupAdvisories(queries, options({ fetch: hanging, timeoutMs: 20 }));
    expect(result.error).toBeTruthy();
    expect(result.index.size).toBe(0);
  });

  it('does nothing when there is nothing to ask', async () => {
    const result = await lookupAdvisories([], options());
    expect(result.index.size).toBe(0);
    expect(result.durationMs).toBe(0);
  });

  it('caps the number of detail lookups', async () => {
    const recorded: Recorded = { urls: [], bodies: [] };
    const ids = Array.from({ length: 20 }, (_, index) => `ID-${index}`);
    await lookupAdvisories(
      [queries[0]!],
      options({
        maxDetailLookups: 3,
        fetch: transport(
          { 'lodash@4.17.15': { ids } },
          Object.fromEntries(ids.map((id) => [id, { ...LODASH_DETAIL, id }])),
          recorded,
        ),
      }),
    );
    expect(recorded.urls.filter((url) => url.includes('/v1/vulns/'))).toHaveLength(3);
  });
});

describe('toAdvisory', () => {
  const query: OsvQuery = { ecosystem: 'npm', name: 'lodash', version: '4.17.15' };

  it('prefers the CVE alias over the database id', () => {
    expect(toAdvisory(LODASH_DETAIL, query).cve).toBe('CVE-2021-23337');
  });

  it('falls back to the database id with no CVE', () => {
    expect(toAdvisory({ id: 'GHSA-only' }, query).cve).toBe('GHSA-only');
  });

  it('maps the ecosystem rating', () => {
    const map: Record<string, string> = {
      CRITICAL: 'critical',
      HIGH: 'high',
      MODERATE: 'medium',
      MEDIUM: 'medium',
      LOW: 'low',
    };
    for (const [rating, expected] of Object.entries(map)) {
      expect(toAdvisory({ database_specific: { severity: rating } }, query).severity).toBe(expected);
    }
  });

  it('treats an unrated advisory as medium, not harmless', () => {
    // Unrated means nobody scored it, which is not the same as low risk.
    expect(toAdvisory({ id: 'X' }, query).severity).toBe('medium');
  });

  it('reads a numeric severity when one is published', () => {
    expect(
      toAdvisory({ id: 'X', severity: [{ type: 'CVSS_V3', score: '9.8' }] }, query).severity,
    ).toBe('critical');
    expect(
      toAdvisory({ id: 'X', severity: [{ type: 'CVSS_V3', score: '5.0' }] }, query).severity,
    ).toBe('medium');
  });

  it('finds the fixed version for the right package', () => {
    const detail = {
      id: 'X',
      affected: [
        {
          package: { ecosystem: 'npm', name: 'something-else' },
          ranges: [{ events: [{ fixed: '9.9.9' }] }],
        },
        {
          package: { ecosystem: 'npm', name: 'lodash' },
          ranges: [{ events: [{ fixed: '4.17.21' }] }],
        },
      ],
    };
    expect(toAdvisory(detail, query).fixedIn).toBe('4.17.21');
  });

  it('says so when no fix is published', () => {
    expect(toAdvisory({ id: 'X' }, query).fixedIn).toBe('a later version');
  });

  it('keeps the summary to one line', () => {
    const advisory = toAdvisory({ id: 'X', summary: 'Line one\nLine two' }, query);
    expect(advisory.summary).toBe('Line one');
  });

  it('falls back to details when there is no summary', () => {
    expect(toAdvisory({ id: 'X', details: 'Longer text' }, query).summary).toBe('Longer text');
  });
});

describe('scanWithAdvisories', () => {
  const files = [
    { filePath: 'package.json', content: MANIFEST, status: 'modified' as const, changedLines: null },
  ];

  it('reports live advisories alongside the bundled ones', async () => {
    const recorded: Recorded = { urls: [], bodies: [] };
    const summary = await scanWithAdvisories(
      files,
      {},
      {
        baseUrl: 'https://osv.test',
        fetch: transport(
          { 'lodash@4.17.15': { ids: ['GHSA-29mw-wpgm-hmr9'] } },
          { 'GHSA-29mw-wpgm-hmr9': LODASH_SECOND },
          recorded,
        ),
      },
    );

    const cves = summary.findings
      .filter((finding) => finding.ruleId === 'dependencies/known-vulnerable-version')
      .map((finding) => finding.title);
    // The live one, which is not in the bundled snapshot.
    expect(cves.some((title) => title.includes('CVE-2020-28500'))).toBe(true);
    // And the bundled one, which the live stub did not return.
    expect(cves.some((title) => title.includes('CVE-2021-23337'))).toBe(true);
    expect(summary.advisoryLookup?.found).toBe(1);
  });

  it('gives each advisory its own finding rather than collapsing them', async () => {
    // Several advisories share one manifest line, so without distinct
    // fingerprints the engine's deduplication would report only one.
    const recorded: Recorded = { urls: [], bodies: [] };
    const summary = await scanWithAdvisories(
      files,
      {},
      {
        baseUrl: 'https://osv.test',
        fetch: transport(
          { 'lodash@4.17.15': { ids: ['GHSA-35jh-r3h4-6jhm', 'GHSA-29mw-wpgm-hmr9'] } },
          { 'GHSA-35jh-r3h4-6jhm': LODASH_DETAIL, 'GHSA-29mw-wpgm-hmr9': LODASH_SECOND },
          recorded,
        ),
      },
    );
    const lodash = summary.findings.filter((finding) => finding.title.includes('lodash'));
    expect(lodash.length).toBeGreaterThanOrEqual(2);
    expect(new Set(lodash.map((finding) => finding.fingerprint)).size).toBe(lodash.length);
  });

  it('never reports less than an offline scan when the lookup fails', async () => {
    const failing = (async () => new Response('boom', { status: 503 })) as unknown as typeof globalThis.fetch;
    const withFailure = await scanWithAdvisories(files, {}, { fetch: failing });
    const offline = await scanWithAdvisories(files, {}, { enabled: false });

    expect(withFailure.advisoryLookup?.error).toBeTruthy();
    expect(withFailure.findings.length).toBeGreaterThanOrEqual(offline.findings.length);
    // The bundled snapshot still fired.
    expect(withFailure.findings.some((f) => f.title.includes('CVE-2021-23337'))).toBe(true);
  });

  it('does not touch the network when switched off', async () => {
    let called = false;
    const spy = (async () => {
      called = true;
      throw new Error('should not be called');
    }) as unknown as typeof globalThis.fetch;
    const summary = await scanWithAdvisories(files, {}, { enabled: false, fetch: spy });
    expect(called).toBe(false);
    expect(summary.advisoryLookup).toBeUndefined();
  });

  it('does not touch the network when there are no dependencies to ask about', async () => {
    let called = false;
    const spy = (async () => {
      called = true;
      throw new Error('should not be called');
    }) as unknown as typeof globalThis.fetch;
    await scanWithAdvisories(
      [{ filePath: 'src/app.ts', content: 'const a = 1;', status: 'modified', changedLines: null }],
      {},
      { fetch: spy },
    );
    expect(called).toBe(false);
  });

  it('does not leak injected advisories into a later plain scan', async () => {
    const recorded: Recorded = { urls: [], bodies: [] };
    await scanWithAdvisories(
      files,
      {},
      {
        baseUrl: 'https://osv.test',
        fetch: transport(
          { 'lodash@4.17.15': { ids: ['GHSA-29mw-wpgm-hmr9'] } },
          { 'GHSA-29mw-wpgm-hmr9': LODASH_SECOND },
          recorded,
        ),
      },
    );
    const offline = await scanWithAdvisories(files, {}, { enabled: false });
    expect(offline.findings.some((f) => f.title.includes('CVE-2020-28500'))).toBe(false);
  });
});
