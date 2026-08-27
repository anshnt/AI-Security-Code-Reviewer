import {
  advisoriesFor,
  editDistance,
  POPULAR_NPM_PACKAGES,
  rangeIsAffected,
  type Ecosystem,
} from '../advisories';
import { advisoryKey, type AdvisoryIndex } from '../osv';
import { makeFinding } from '../source';
import type { Finding, Rule, ScanTarget } from '../types';

/**
 * Dependency hygiene.
 *
 * A dependency change is one of the highest-leverage things in a diff: a single
 * line adds thousands of lines of code you did not write, running with your
 * privileges, at install time and at runtime. This rule reads the manifest
 * formats directly and reports four distinct problems:
 *
 *   - a declared range that permits a version with a known advisory;
 *   - an unpinned or unbounded range, which makes builds non-reproducible and
 *     lets a future compromised release in without a code change;
 *   - a source that is not the registry (git URL, plain HTTP, local tarball);
 *   - an install hook, which executes on `npm install` before any code review
 *     of the dependency has happened.
 */

/**
 * Advisories supplied from outside the bundled snapshot, set before a scan.
 *
 * A module-level slot rather than a rule parameter because `Rule.check` is
 * synchronous by design - the analyzers must not each be able to make network
 * calls - while an advisory lookup is inherently asynchronous. The engine does
 * the lookup once, up front, and hands the answer in.
 */
let injectedAdvisories: AdvisoryIndex = new Map();

export function setInjectedAdvisories(index: AdvisoryIndex): void {
  injectedAdvisories = index;
}

export function clearInjectedAdvisories(): void {
  injectedAdvisories = new Map();
}

interface Manifest {
  ecosystem: Ecosystem;
  matches(filePath: string): boolean;
  /** Extracts `[name, range, lineNumber]` for every declared dependency. */
  parse(target: ScanTarget): DeclaredDependency[];
}

interface DeclaredDependency {
  name: string;
  range: string;
  line: number;
  raw: string;
  /** Development-only dependencies carry less production risk. */
  dev: boolean;
}

const NPM_MANIFEST: Manifest = {
  ecosystem: 'npm',
  matches: (filePath) => /(^|\/)package\.json$/.test(filePath),
  parse(target) {
    const out: DeclaredDependency[] = [];
    let section: string | null = null;
    target.lines.forEach((raw, index) => {
      const sectionMatch = /^\s*"(dependencies|devDependencies|peerDependencies|optionalDependencies)"\s*:/.exec(raw);
      if (sectionMatch) {
        section = sectionMatch[1]!;
        return;
      }
      if (/^\s*[}\]]/.test(raw)) {
        if (section && /^\s{0,4}[}\]]/.test(raw)) section = null;
        return;
      }
      if (!section) return;
      const entry = /^\s*"(@?[A-Za-z0-9._\-/]+)"\s*:\s*"([^"]*)"/.exec(raw);
      if (!entry) return;
      out.push({
        name: entry[1]!,
        range: entry[2]!,
        line: index + 1,
        raw,
        dev: section !== 'dependencies' && section !== 'peerDependencies',
      });
    });
    return out;
  },
};

const PIP_MANIFEST: Manifest = {
  ecosystem: 'pypi',
  matches: (filePath) => /(^|\/)(?:requirements[^/]*\.txt|constraints\.txt|Pipfile|pyproject\.toml)$/.test(filePath),
  parse(target) {
    const out: DeclaredDependency[] = [];
    target.lines.forEach((raw, index) => {
      const line = raw.split('#')[0]!.trim();
      if (!line || /^-{1,2}/.test(line) || /^\[/.test(line)) return;
      const entry = /^"?([A-Za-z0-9._\-]+)"?\s*(?:\[[^\]]*\])?\s*(==|>=|<=|~=|>|<|\^|=)?\s*"?([0-9][0-9A-Za-z.\-*]*)?"?/.exec(line);
      if (!entry?.[1]) return;
      out.push({
        name: entry[1],
        range: `${entry[2] ?? ''}${entry[3] ?? ''}`,
        line: index + 1,
        raw,
        dev: /dev|test/i.test(target.filePath),
      });
    });
    return out;
  },
};

const GO_MANIFEST: Manifest = {
  ecosystem: 'go',
  matches: (filePath) => /(^|\/)go\.mod$/.test(filePath),
  parse(target) {
    const out: DeclaredDependency[] = [];
    target.lines.forEach((raw, index) => {
      const entry = /^\s*(?:require\s+)?([a-z0-9.\-]+\.[a-z]{2,}\/[^\s]+)\s+v([0-9][^\s]*)/.exec(raw);
      if (!entry) return;
      out.push({ name: entry[1]!, range: entry[2]!, line: index + 1, raw, dev: false });
    });
    return out;
  },
};

const MAVEN_MANIFEST: Manifest = {
  ecosystem: 'maven',
  matches: (filePath) => /(^|\/)(?:pom\.xml|build\.gradle(?:\.kts)?)$/.test(filePath),
  parse(target) {
    const out: DeclaredDependency[] = [];
    // Gradle short form: implementation 'group:artifact:version'
    target.lines.forEach((raw, index) => {
      const gradle = /["']([A-Za-z0-9._\-]+:[A-Za-z0-9._\-]+):([0-9][^"']*)["']/.exec(raw);
      if (gradle) {
        out.push({
          name: gradle[1]!,
          range: gradle[2]!,
          line: index + 1,
          raw,
          dev: /testImplementation|testCompile/.test(raw),
        });
      }
    });
    // Maven XML form spans lines; join and walk the dependency blocks.
    const joined = target.lines.join('\n');
    const blockPattern =
      /<dependency>([\s\S]*?)<\/dependency>/g;
    let block: RegExpExecArray | null;
    while ((block = blockPattern.exec(joined))) {
      const body = block[1]!;
      const group = /<groupId>\s*([^<\s]+)\s*<\/groupId>/.exec(body)?.[1];
      const artifact = /<artifactId>\s*([^<\s]+)\s*<\/artifactId>/.exec(body)?.[1];
      const version = /<version>\s*([^<\s]+)\s*<\/version>/.exec(body)?.[1];
      if (!group || !artifact || !version) continue;
      const line = joined.slice(0, block.index).split('\n').length;
      out.push({
        name: `${group}:${artifact}`,
        range: version,
        line,
        raw: `${group}:${artifact}:${version}`,
        dev: /<scope>\s*test\s*<\/scope>/.test(body),
      });
    }
    return out;
  },
};

const GEM_MANIFEST: Manifest = {
  ecosystem: 'rubygems',
  matches: (filePath) => /(^|\/)Gemfile$/.test(filePath),
  parse(target) {
    const out: DeclaredDependency[] = [];
    target.lines.forEach((raw, index) => {
      const entry = /^\s*gem\s+["']([A-Za-z0-9._\-]+)["'](?:\s*,\s*["']([^"']+)["'])?/.exec(raw);
      if (!entry?.[1]) return;
      out.push({ name: entry[1], range: entry[2] ?? '', line: index + 1, raw, dev: /group:\s*:(?:test|development)/.test(raw) });
    });
    return out;
  },
};

const COMPOSER_MANIFEST: Manifest = {
  ecosystem: 'composer',
  matches: (filePath) => /(^|\/)composer\.json$/.test(filePath),
  parse(target) {
    const out: DeclaredDependency[] = [];
    let section: string | null = null;
    target.lines.forEach((raw, index) => {
      const sectionMatch = /^\s*"(require|require-dev)"\s*:/.exec(raw);
      if (sectionMatch) {
        section = sectionMatch[1]!;
        return;
      }
      if (/^\s{0,4}\}/.test(raw)) section = null;
      if (!section) return;
      const entry = /^\s*"([A-Za-z0-9._\-]+\/[A-Za-z0-9._\-]+)"\s*:\s*"([^"]*)"/.exec(raw);
      if (!entry) return;
      out.push({ name: entry[1]!, range: entry[2]!, line: index + 1, raw, dev: section === 'require-dev' });
    });
    return out;
  },
};

const MANIFESTS = [NPM_MANIFEST, PIP_MANIFEST, GO_MANIFEST, MAVEN_MANIFEST, GEM_MANIFEST, COMPOSER_MANIFEST];

/**
 * Every dependency a file declares, with its ecosystem.
 *
 * Exported so the engine can gather them for an advisory lookup before scanning,
 * using exactly the same parsing the rule itself uses. Two parsers that disagree
 * about what a manifest declares would produce advisories for packages the rule
 * never checks.
 */
export function parseManifest(
  target: ScanTarget,
): { ecosystem: Ecosystem; name: string; range: string; line: number }[] {
  const manifest = MANIFESTS.find((entry) => entry.matches(target.filePath));
  if (!manifest) return [];
  return manifest.parse(target).map((dependency) => ({
    ecosystem: manifest.ecosystem,
    name: dependency.name,
    range: dependency.range,
    line: dependency.line,
  }));
}

/** Ranges with no upper bound at all. */
const UNBOUNDED_RANGE = /^\s*(?:\*|x|latest|>=?[^,\s]*|)\s*$/i;
/** Sources fetched from somewhere other than the registry. */
const NON_REGISTRY_SOURCE =
  /^(?:git(?:\+[a-z]+)?:|https?:|ssh:|file:|link:|github:|gitlab:|bitbucket:|[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:#.*)?$)/;

export const dependenciesRule: Rule = {
  id: 'dependencies',
  category: 'dependencies',
  description:
    'Reviews dependency manifests for versions with known advisories, unbounded ranges, non-registry sources, install hooks and likely typosquats.',
  languages: ['*'],
  skipLanguages: ['documentation'],

  check(target: ScanTarget): Finding[] {
    const manifest = MANIFESTS.find((entry) => entry.matches(target.filePath));
    if (!manifest) return [];

    const findings: Finding[] = [];
    const changed = target.changedLines;
    const isRelevant = (line: number): boolean => changed === null || changed.has(line);

    for (const dependency of manifest.parse(target)) {
      if (!isRelevant(dependency.line)) continue;

      // --- Known advisories ------------------------------------------------
      // Injected advisories were looked up for the exact declared version, so
      // the source has already decided the version is affected and there is no
      // range check to redo. Bundled ones carry a fixed-version bound instead.
      const injected = injectedAdvisories.get(advisoryKey(manifest.ecosystem, dependency.name)) ?? [];
      const bundled = advisoriesFor(manifest.ecosystem, dependency.name).filter((advisory) =>
        rangeIsAffected(dependency.range, advisory),
      );
      const seenIdentifiers = new Set(injected.map((advisory) => advisory.cve));

      for (const advisory of [...injected, ...bundled.filter((a) => !seenIdentifiers.has(a.cve))]) {
        findings.push(
          makeFinding(target, 'dependencies', {
            ruleId: 'dependencies/known-vulnerable-version',
            severity: dependency.dev ? downgrade(advisory.severity) : advisory.severity,
            confidence: 'high',
            title: `${dependency.name}@${dependency.range} is affected by ${advisory.cve}`,
            description:
              `${advisory.summary} The declared range permits versions below ${advisory.fixedIn}, which ` +
              `are affected.${dependency.dev ? ' This is a development dependency, so exposure is limited to build and CI machines - which are still a credible target.' : ''}`,
            remediation:
              `Raise the constraint to \`>=${advisory.fixedIn}\` (or the nearest release your other ` +
              'constraints allow) and refresh the lockfile so the resolved version actually changes. ' +
              'For a transitive dependency, use an override/resolution pin until the direct parent updates.',
            line: dependency.line,
            evidence: dependency.raw,
            // Several advisories can name the same dependency on the same line;
            // without the identifier they would fingerprint alike and all but
            // one would be deduplicated away.
            fingerprintExtra: advisory.cve,
            cwe: ['CWE-1395', 'CWE-1104'],
          }),
        );
      }

      // --- Non-registry sources -------------------------------------------
      if (NON_REGISTRY_SOURCE.test(dependency.range)) {
        const insecure = /^http:/.test(dependency.range);
        const unpinned =
          /^(?:git|github:|gitlab:|bitbucket:|https?:)/.test(dependency.range) &&
          !/#[0-9a-f]{7,40}\b/.test(dependency.range);
        if (insecure || unpinned) {
          findings.push(
            makeFinding(target, 'dependencies', {
              ruleId: insecure ? 'dependencies/insecure-transport' : 'dependencies/unpinned-git-source',
              severity: insecure ? 'high' : 'medium',
              confidence: 'high',
              title: insecure
                ? `${dependency.name} is fetched over plain HTTP`
                : `${dependency.name} is installed from a git ref that can move`,
              description: insecure
                ? 'An unencrypted fetch can be intercepted and the archive replaced in transit, which means ' +
                  'arbitrary code running in your build with no signature to check.'
                : 'A branch or tag can be repointed at any commit after review, so the code that passed ' +
                  'review is not necessarily the code that installs. Tags are mutable in git.',
              remediation: insecure
                ? 'Use the `https` URL, or better, publish the package to your registry and depend on it by version.'
                : 'Pin the dependency to a full commit SHA (`...#<40-char-sha>`), or vendor the code and review ' +
                  'it as part of your own tree.',
              line: dependency.line,
              evidence: dependency.raw,
              cwe: ['CWE-494', 'CWE-1357'],
            }),
          );
        }
        continue; // Range checks below do not apply to non-registry sources.
      }

      // --- Unbounded ranges -----------------------------------------------
      if (UNBOUNDED_RANGE.test(dependency.range) && !dependency.dev) {
        findings.push(
          makeFinding(target, 'dependencies', {
            ruleId: 'dependencies/unbounded-version-range',
            severity: 'medium',
            confidence: 'high',
            title: `${dependency.name} has no upper version bound (\`${dependency.range || 'empty'}\`)`,
            description:
              'Any future release satisfies this constraint, including a major version with breaking ' +
              'changes and - more importantly - a release published after a maintainer account compromise. ' +
              'Builds also stop being reproducible: the same commit resolves differently over time.',
            remediation:
              'Declare a bounded range (`^1.4.0`, `~=2.1`) and commit the lockfile so CI and production ' +
              'install exactly what was reviewed. Let a bot propose upgrades so they arrive as reviewable diffs.',
            line: dependency.line,
            evidence: dependency.raw,
            cwe: ['CWE-1104'],
          }),
        );
      }

      // --- Typosquat near-miss --------------------------------------------
      if (manifest.ecosystem === 'npm' && !dependency.name.startsWith('@')) {
        for (const popular of POPULAR_NPM_PACKAGES) {
          if (dependency.name === popular) break;
          if (Math.abs(dependency.name.length - popular.length) > 2) continue;
          const distance = editDistance(dependency.name, popular, 1);
          if (distance === 1) {
            findings.push(
              makeFinding(target, 'dependencies', {
                ruleId: 'dependencies/possible-typosquat',
                severity: 'high',
                confidence: 'low',
                title: `\`${dependency.name}\` is one character away from \`${popular}\``,
                description:
                  'Typosquatting is a routine supply-chain attack: an attacker publishes a package whose ' +
                  'name differs from a popular one by a single character and waits for a typo. The ' +
                  'install script then runs with the developer\'s credentials on their machine and in CI.',
                remediation:
                  `Confirm this is the package you meant. If you wanted \`${popular}\`, fix the name and ` +
                  'remove the installed copy along with its lockfile entries. If the name is correct, ' +
                  'check the package\'s repository, download count and publish history before keeping it.',
                line: dependency.line,
                evidence: dependency.raw,
                cwe: ['CWE-1357'],
              }),
            );
            break;
          }
        }
      }
    }

    // --- Install hooks ------------------------------------------------------
    if (manifest.ecosystem === 'npm') {
      target.lines.forEach((raw, index) => {
        if (!isRelevant(index + 1)) return;
        const hook = /"(preinstall|install|postinstall|prepare|prepublish)"\s*:\s*"([^"]*)"/.exec(raw);
        if (!hook) return;
        const command = hook[2] ?? '';
        // A local build step is normal; fetching and piping into a shell is not.
        const suspicious = /\b(?:curl|wget|nc|bash\s+-c|sh\s+-c|node\s+-e|eval|base64|chmod\s+\+x|\|\s*(?:sh|bash))\b/.test(
          command,
        );
        findings.push(
          makeFinding(target, 'dependencies', {
            ruleId: 'dependencies/install-hook-added',
            severity: suspicious ? 'critical' : 'low',
            confidence: suspicious ? 'high' : 'medium',
            title: `\`${hook[1]}\` script ${suspicious ? 'runs a network-fetched command' : 'added to package.json'}`,
            description: suspicious
              ? 'This hook downloads and executes code during `npm install`, before any test or review ' +
                'runs. That is the exact mechanism used by supply-chain attacks to steal developer and CI ' +
                'credentials, and it fires on every machine that installs this package.'
              : 'Install hooks execute automatically on `npm install`, on every contributor machine and in ' +
                'CI. Worth an explicit look in review even when the command is benign.',
            remediation: suspicious
              ? 'Remove the network fetch. Vendor the artefact, or download it in an explicit build step ' +
                'with a checksum verification, so the code that runs is the code that was reviewed.'
              : 'Keep hooks to local, deterministic build steps and prefer an explicit `npm run build` in CI ' +
                'so the work is visible rather than implicit.',
            line: index + 1,
            evidence: raw,
            cwe: ['CWE-829'],
          }),
        );
      });
    }

    return findings;
  },
};

function downgrade(severity: Finding['severity']): Finding['severity'] {
  switch (severity) {
    case 'critical':
      return 'high';
    case 'high':
      return 'medium';
    case 'medium':
      return 'low';
    default:
      return 'low';
  }
}
