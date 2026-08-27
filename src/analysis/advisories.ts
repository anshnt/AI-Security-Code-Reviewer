/**
 * Offline advisory snapshot.
 *
 * A pull-request reviewer has to answer "is this dependency safe?" without a
 * network round trip on the hot path, so a curated set of high-impact,
 * widely-encountered advisories ships with the tool. Every entry is a real,
 * published CVE with a known fixed version.
 *
 * This is deliberately a floor, not a replacement for a full vulnerability
 * database: it covers the packages that actually show up in dependency bumps.
 * Sync against a live source (OSV, GitHub Advisory Database) for exhaustive
 * coverage.
 */

export type Ecosystem = 'npm' | 'pypi' | 'maven' | 'go' | 'rubygems' | 'composer';

export interface Advisory {
  ecosystem: Ecosystem;
  /** Package name as it appears in the manifest. */
  name: string;
  /** Every version strictly below this is affected. */
  fixedIn: string;
  /** Versions at or above this are affected (for advisories with a lower bound). */
  introducedIn?: string;
  cve: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  summary: string;
}

export const ADVISORIES: Advisory[] = [
  // ---- npm ---------------------------------------------------------------
  {
    ecosystem: 'npm',
    name: 'lodash',
    fixedIn: '4.17.21',
    cve: 'CVE-2021-23337',
    severity: 'high',
    summary: 'Command injection via the template function.',
  },
  {
    ecosystem: 'npm',
    name: 'minimist',
    fixedIn: '1.2.6',
    cve: 'CVE-2021-44906',
    severity: 'critical',
    summary: 'Prototype pollution through crafted argument names.',
  },
  {
    ecosystem: 'npm',
    name: 'jsonwebtoken',
    fixedIn: '9.0.0',
    cve: 'CVE-2022-23540',
    severity: 'high',
    summary: 'Insecure default algorithm handling allows signature bypass in some configurations.',
  },
  {
    ecosystem: 'npm',
    name: 'node-fetch',
    fixedIn: '2.6.7',
    cve: 'CVE-2022-0235',
    severity: 'high',
    summary: 'Cookie and Authorization headers leak to a third-party host across redirects.',
  },
  {
    ecosystem: 'npm',
    name: 'follow-redirects',
    fixedIn: '1.15.6',
    cve: 'CVE-2024-28849',
    severity: 'medium',
    summary: 'Proxy-Authorization header preserved across cross-host redirects.',
  },
  {
    ecosystem: 'npm',
    name: 'axios',
    fixedIn: '1.6.0',
    cve: 'CVE-2023-45857',
    severity: 'medium',
    summary: 'XSRF token leaked to third-party hosts in the request.',
  },
  {
    ecosystem: 'npm',
    name: 'tar',
    fixedIn: '6.1.9',
    cve: 'CVE-2021-32803',
    severity: 'high',
    summary: 'Arbitrary file write via insufficient symlink protection during extraction.',
  },
  {
    ecosystem: 'npm',
    name: 'ws',
    fixedIn: '7.4.6',
    cve: 'CVE-2021-32640',
    severity: 'medium',
    summary: 'Denial of service through a specially crafted Sec-Websocket-Protocol header.',
  },
  {
    ecosystem: 'npm',
    name: 'semver',
    fixedIn: '7.5.2',
    cve: 'CVE-2022-25883',
    severity: 'medium',
    summary: 'Regular expression denial of service in range parsing.',
  },
  {
    ecosystem: 'npm',
    name: 'braces',
    fixedIn: '3.0.3',
    cve: 'CVE-2024-4068',
    severity: 'high',
    summary: 'Uncontrolled resource consumption on crafted brace patterns.',
  },
  {
    ecosystem: 'npm',
    name: 'moment',
    fixedIn: '2.29.4',
    cve: 'CVE-2022-31129',
    severity: 'high',
    summary: 'Regular expression denial of service in string-to-date parsing.',
  },
  {
    ecosystem: 'npm',
    name: 'qs',
    fixedIn: '6.2.4',
    cve: 'CVE-2017-1000048',
    severity: 'high',
    summary: 'Prototype pollution through crafted query strings.',
  },
  {
    ecosystem: 'npm',
    name: 'y18n',
    fixedIn: '4.0.1',
    cve: 'CVE-2020-7774',
    severity: 'high',
    summary: 'Prototype pollution.',
  },
  {
    ecosystem: 'npm',
    name: 'ip',
    fixedIn: '2.0.1',
    cve: 'CVE-2024-29415',
    severity: 'high',
    summary: 'isPublic misclassifies some addresses, enabling SSRF filter bypass.',
  },
  {
    ecosystem: 'npm',
    name: 'json5',
    fixedIn: '2.2.2',
    cve: 'CVE-2022-46175',
    severity: 'high',
    summary: 'Prototype pollution via __proto__ in parsed documents.',
  },
  {
    ecosystem: 'npm',
    name: 'jquery',
    fixedIn: '3.5.0',
    cve: 'CVE-2020-11022',
    severity: 'medium',
    summary: 'Cross-site scripting when passing untrusted HTML to DOM manipulation methods.',
  },
  {
    ecosystem: 'npm',
    name: 'next',
    fixedIn: '13.5.1',
    cve: 'CVE-2023-46298',
    severity: 'medium',
    summary: 'Cache poisoning leading to a denial of service on the server component.',
  },
  {
    ecosystem: 'npm',
    name: 'express',
    fixedIn: '4.19.2',
    cve: 'CVE-2024-29041',
    severity: 'medium',
    summary: 'Open redirect through malformed URLs passed to response.location.',
  },
  {
    ecosystem: 'npm',
    name: 'cookie',
    fixedIn: '0.7.0',
    cve: 'CVE-2024-47764',
    severity: 'low',
    summary: 'Out-of-bounds character handling permits cookie field injection.',
  },
  {
    ecosystem: 'npm',
    name: 'path-to-regexp',
    fixedIn: '0.1.10',
    cve: 'CVE-2024-45296',
    severity: 'high',
    summary: 'Backtracking regular expression enables denial of service.',
  },

  // ---- PyPI --------------------------------------------------------------
  {
    ecosystem: 'pypi',
    name: 'pyyaml',
    fixedIn: '5.4',
    cve: 'CVE-2020-14343',
    severity: 'critical',
    summary: 'Arbitrary code execution through yaml.full_load and the default loader.',
  },
  {
    ecosystem: 'pypi',
    name: 'requests',
    fixedIn: '2.31.0',
    cve: 'CVE-2023-32681',
    severity: 'medium',
    summary: 'Proxy-Authorization header leaked to the destination on redirect.',
  },
  {
    ecosystem: 'pypi',
    name: 'urllib3',
    fixedIn: '1.26.18',
    cve: 'CVE-2023-45803',
    severity: 'medium',
    summary: 'Request body not stripped after a 303 redirect, leaking data.',
  },
  {
    ecosystem: 'pypi',
    name: 'flask',
    fixedIn: '2.2.5',
    cve: 'CVE-2023-30861',
    severity: 'high',
    summary: 'Session cookie may be cached by a proxy and served to another client.',
  },
  {
    ecosystem: 'pypi',
    name: 'django',
    fixedIn: '4.2.7',
    introducedIn: '4.2',
    cve: 'CVE-2023-46695',
    severity: 'medium',
    summary: 'Denial of service in UsernameField normalisation on Windows.',
  },
  {
    ecosystem: 'pypi',
    name: 'jinja2',
    fixedIn: '3.1.3',
    cve: 'CVE-2024-22195',
    severity: 'medium',
    summary: 'Cross-site scripting through the xmlattr filter.',
  },
  {
    ecosystem: 'pypi',
    name: 'pillow',
    fixedIn: '10.2.0',
    cve: 'CVE-2023-50447',
    severity: 'high',
    summary: 'Arbitrary code execution via ImageMath.eval environment keys.',
  },
  {
    ecosystem: 'pypi',
    name: 'cryptography',
    fixedIn: '42.0.4',
    cve: 'CVE-2024-26130',
    severity: 'medium',
    summary: 'NULL pointer dereference when loading a malformed PKCS#12 file.',
  },
  {
    ecosystem: 'pypi',
    name: 'setuptools',
    fixedIn: '65.5.1',
    cve: 'CVE-2022-40897',
    severity: 'medium',
    summary: 'Regular expression denial of service in package index parsing.',
  },
  {
    ecosystem: 'pypi',
    name: 'aiohttp',
    fixedIn: '3.9.2',
    cve: 'CVE-2024-23334',
    severity: 'high',
    summary: 'Directory traversal when follow_symlinks is enabled on a static route.',
  },

  // ---- Maven -------------------------------------------------------------
  {
    ecosystem: 'maven',
    name: 'org.apache.logging.log4j:log4j-core',
    fixedIn: '2.17.1',
    cve: 'CVE-2021-44228',
    severity: 'critical',
    summary: 'Remote code execution through JNDI lookup in logged messages (Log4Shell).',
  },
  {
    ecosystem: 'maven',
    name: 'com.fasterxml.jackson.core:jackson-databind',
    fixedIn: '2.13.4.2',
    cve: 'CVE-2022-42003',
    severity: 'high',
    summary: 'Deeply nested input causes resource exhaustion during deserialization.',
  },
  {
    ecosystem: 'maven',
    name: 'org.springframework:spring-beans',
    fixedIn: '5.3.18',
    cve: 'CVE-2022-22965',
    severity: 'critical',
    summary: 'Remote code execution through data binding on JDK 9+ (Spring4Shell).',
  },
  {
    ecosystem: 'maven',
    name: 'org.yaml:snakeyaml',
    fixedIn: '2.0',
    cve: 'CVE-2022-1471',
    severity: 'critical',
    summary: 'Remote code execution through unsafe constructor deserialization.',
  },

  // ---- Go ----------------------------------------------------------------
  {
    ecosystem: 'go',
    name: 'golang.org/x/net',
    fixedIn: '0.23.0',
    cve: 'CVE-2023-45288',
    severity: 'medium',
    summary: 'HTTP/2 CONTINUATION flood permits denial of service.',
  },
  {
    ecosystem: 'go',
    name: 'golang.org/x/crypto',
    fixedIn: '0.17.0',
    cve: 'CVE-2023-48795',
    severity: 'medium',
    summary: 'SSH transport prefix truncation weakens channel integrity (Terrapin).',
  },

  // ---- RubyGems ----------------------------------------------------------
  {
    ecosystem: 'rubygems',
    name: 'rack',
    fixedIn: '2.2.6.4',
    cve: 'CVE-2023-27530',
    severity: 'high',
    summary: 'Unbounded multipart parsing enables denial of service.',
  },
  {
    ecosystem: 'rubygems',
    name: 'nokogiri',
    fixedIn: '1.13.10',
    cve: 'CVE-2022-23476',
    severity: 'medium',
    summary: 'Unchecked return value in XML parsing can crash the process.',
  },

  // ---- Composer ----------------------------------------------------------
  {
    ecosystem: 'composer',
    name: 'symfony/http-kernel',
    fixedIn: '5.4.20',
    cve: 'CVE-2022-24894',
    severity: 'medium',
    summary: 'Sensitive request headers may be stored in the HTTP cache.',
  },
  {
    ecosystem: 'composer',
    name: 'guzzlehttp/guzzle',
    fixedIn: '7.4.5',
    cve: 'CVE-2022-31090',
    severity: 'medium',
    summary: 'Authorization header not cleared on cross-host redirect.',
  },
];

/** Popular packages that attract typosquats, used for the near-miss check. */
export const POPULAR_NPM_PACKAGES = [
  'react', 'lodash', 'axios', 'express', 'chalk', 'commander', 'debug', 'dotenv',
  'moment', 'request', 'colors', 'jquery', 'webpack', 'babel', 'eslint', 'jest',
  'typescript', 'mocha', 'redux', 'vue', 'angular', 'socket.io', 'mongoose',
  'bluebird', 'underscore', 'async', 'body-parser', 'cors', 'crossenv',
];

const ADVISORY_INDEX = new Map<string, Advisory[]>();
for (const advisory of ADVISORIES) {
  const key = `${advisory.ecosystem}:${advisory.name.toLowerCase()}`;
  const bucket = ADVISORY_INDEX.get(key);
  if (bucket) bucket.push(advisory);
  else ADVISORY_INDEX.set(key, [advisory]);
}

export function advisoriesFor(ecosystem: Ecosystem, name: string): Advisory[] {
  return ADVISORY_INDEX.get(`${ecosystem}:${name.toLowerCase()}`) ?? [];
}

/**
 * Semantic-version comparison over dot-separated numeric parts. Pre-release
 * suffixes sort below the release they precede, which is what we want when
 * deciding whether `1.2.3-beta.1` is still affected by an advisory fixed in
 * `1.2.3`.
 */
export function compareVersions(left: string, right: string): number {
  const split = (value: string): { parts: number[]; pre: string } => {
    const [core, ...rest] = value.replace(/^[^\d]*/, '').split('-');
    return {
      parts: (core ?? '').split('.').map((part) => Number.parseInt(part, 10) || 0),
      pre: rest.join('-'),
    };
  };
  const a = split(left);
  const b = split(right);
  const length = Math.max(a.parts.length, b.parts.length);
  for (let i = 0; i < length; i += 1) {
    const diff = (a.parts[i] ?? 0) - (b.parts[i] ?? 0);
    if (diff !== 0) return diff > 0 ? 1 : -1;
  }
  if (a.pre === b.pre) return 0;
  if (!a.pre) return 1;
  if (!b.pre) return -1;
  return a.pre < b.pre ? -1 : 1;
}

/** Strips range operators so `^1.2.3` and `>=1.2.3` yield the lowest allowed version. */
export function lowestSatisfyingVersion(range: string): string | null {
  const cleaned = range.trim().replace(/^[v=\s]+/, '');
  const match = /(\d+(?:\.\d+)*(?:\.\d+)?(?:-[0-9A-Za-z.\-]+)?)/.exec(cleaned);
  return match?.[1] ?? null;
}

/** True when a declared range permits at least one version affected by the advisory. */
export function rangeIsAffected(range: string, advisory: Advisory): boolean {
  const lowest = lowestSatisfyingVersion(range);
  if (!lowest) return false;
  if (advisory.introducedIn && compareVersions(lowest, advisory.introducedIn) < 0) return false;
  return compareVersions(lowest, advisory.fixedIn) < 0;
}

/** Levenshtein distance, capped for early exit on obviously distant names. */
export function editDistance(a: string, b: string, cap = 3): number {
  if (Math.abs(a.length - b.length) > cap) return cap + 1;
  let previous = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i += 1) {
    const current = [i];
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      current[j] = Math.min(
        (current[j - 1] ?? 0) + 1,
        (previous[j] ?? 0) + 1,
        (previous[j - 1] ?? 0) + cost,
      );
    }
    previous = current;
    if (Math.min(...current) > cap) return cap + 1;
  }
  return previous[b.length] ?? cap + 1;
}
