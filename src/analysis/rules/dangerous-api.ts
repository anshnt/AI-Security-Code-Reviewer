// security-review-ignore-file dangerous-api, sql-injection, authentication
// This file's content is a table of patterns that *describe* unsafe code. The
// analyzers would otherwise match their own definitions, which is noise rather
// than signal - the strings here are never executed.
import { blankStringLiterals, enclosingBlock, isCommentLine, makeFinding } from '../source';
import { buildTaintMap, taintStrength, type TaintStrength } from '../taint';
import type { Finding, Rule, ScanTarget } from '../types';

/**
 * Dangerous API usage.
 *
 * Functions in this list are not bugs by themselves - `exec`, `eval` and
 * `unserialize` all have legitimate uses. What makes them findings is reaching
 * them with data the caller controls. So each entry declares whether it is
 * unconditionally dangerous (`always`) or only dangerous when tainted
 * (`onTaint`), and severity is raised when the taint map connects the call to a
 * request.
 */

interface Sink {
  id: string;
  pattern: RegExp;
  /** `always`: report regardless of input. `onTaint`: only with a taint signal. */
  trigger: 'always' | 'onTaint';
  baseSeverity: Finding['severity'];
  title: string;
  description: string;
  remediation: string;
  cwe: string[];
  languages?: ScanTarget['language'][];
  /** If this matches nearby, the sink is already used safely. */
  negate?: RegExp;
}

const SINKS: Sink[] = [
  // --- Arbitrary code execution -------------------------------------------
  {
    id: 'eval',
    pattern: /(?<![.\w$])eval\s*\(|new\s+Function\s*\(|\bvm\s*\.\s*runIn(?:This|New)Context\s*\(|\bassert\s*\(\s*\$|create_function\s*\(/,
    trigger: 'always',
    baseSeverity: 'high',
    title: 'Dynamic code evaluation',
    description:
      'The argument is compiled and run as program code with the full privileges of the process. If any ' +
      'part of it can be influenced from outside, this is remote code execution rather than an injection ' +
      'into some narrower grammar. `eval` also defeats bundlers, minifiers, CSP and static analysis.',
    remediation:
      'There is almost always a non-eval formulation: `JSON.parse` for data, a lookup table for dynamic ' +
      'dispatch, `Number()`/`parseInt` for numeric strings, a real expression parser for user formulas. ' +
      'If a sandbox is genuinely needed, run untrusted code out of process with a hard resource limit.',
    cwe: ['CWE-95', 'CWE-94'],
  },
  {
    id: 'python-exec',
    pattern: /(?<![.\w$])(?:exec|execfile|compile)\s*\(/,
    trigger: 'always',
    baseSeverity: 'high',
    languages: ['python'],
    title: 'Python dynamic code execution',
    description:
      '`exec` and `compile` turn a string into running code with the privileges of the process. Any part ' +
      'of that string that can be influenced from outside becomes remote code execution.',
    remediation:
      'Replace it with an explicit construct: a dict lookup for dynamic dispatch, `ast.literal_eval` for ' +
      'data, `getattr` against an allow-list for dynamic attribute access, or `importlib` for plugins.',
    cwe: ['CWE-95', 'CWE-94'],
  },
  {
    id: 'settimeout-string',
    pattern: /set(?:Timeout|Interval)\s*\(\s*["'`]/,
    trigger: 'always',
    baseSeverity: 'medium',
    title: 'Timer scheduled with a code string',
    description:
      'Passing a string to `setTimeout`/`setInterval` makes the runtime evaluate it as code, with the same ' +
      'consequences as `eval`.',
    remediation: 'Pass a function reference or arrow function instead of a string.',
    cwe: ['CWE-95'],
  },

  // --- Command injection ---------------------------------------------------
  {
    id: 'shell-exec',
    pattern:
      /\bchild_process\s*\.\s*exec(?:Sync)?\s*\(|\bcp\s*\.\s*exec(?:Sync)?\s*\(|(?<![.\w$])exec(?:Sync|File|FileSync)?\s*\(|\bos\s*\.\s*(?:system|popen)\s*\(|\bsubprocess\s*\.\s*(?:call|run|Popen|check_output|check_call)\s*\(|\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|\bProcessBuilder\s*\(|(?<![.\w$])shell_exec\s*\(|(?<![.\w$])passthru\s*\(|(?<![.\w$])popen\s*\(|(?<![.\w$])system\s*\(|\bIO\s*\.\s*popen\s*\(/,
    trigger: 'onTaint',
    baseSeverity: 'critical',
    title: 'Shell command built from untrusted input',
    description:
      'The command string is handed to a shell, which interprets `;`, `|`, `&&`, `$(...)` and backticks. ' +
      'A value containing any of those runs an attacker-chosen command as the service account - quoting ' +
      'and blocklisting reliably fail here because the shell has many equivalent syntaxes.',
    remediation:
      'Do not involve a shell. Use the argument-array form so the OS passes arguments directly: ' +
      '`spawn("git", ["clone", url])`, `subprocess.run(["git","clone",url])` (no `shell=True`), ' +
      '`ProcessBuilder("git","clone",url)`. Where a shell is unavoidable, validate the value against a ' +
      'strict allow-list pattern first.',
    cwe: ['CWE-78'],
  },
  {
    id: 'backtick-command-substitution',
    pattern: /`[^`]*\$[({A-Za-z_]/,
    trigger: 'onTaint',
    baseSeverity: 'critical',
    languages: ['shell', 'ruby', 'php'],
    title: 'Backtick command substitution containing a variable',
    description:
      'Backticks run their contents through a shell and substitute the output. A variable inside them is ' +
      'expanded before execution, so a value containing `;` or `$(...)` runs an attacker-chosen command.',
    remediation:
      'Quote the expansion ("$var") to stop word splitting, and prefer passing the value as an argument to ' +
      'a program rather than interpolating it into a command line. In Ruby use `system("cmd", arg)` with ' +
      'separate arguments instead of backticks.',
    cwe: ['CWE-78'],
  },
  {
    id: 'shell-true',
    pattern: /shell\s*[:=]\s*(?:true|True)\b/,
    trigger: 'always',
    baseSeverity: 'medium',
    title: 'Subprocess spawned with a shell',
    description:
      '`shell: true` reintroduces shell metacharacter interpretation even when arguments are passed as an ' +
      'array, so the array form no longer protects you.',
    remediation:
      'Drop the flag and pass the executable and its arguments separately. If you need pipes or ' +
      'redirection, build the pipeline in code rather than delegating to the shell.',
    cwe: ['CWE-78'],
  },

  // --- Unsafe deserialization ---------------------------------------------
  {
    id: 'unsafe-deserialization',
    pattern:
      /\bpickle\s*\.\s*loads?\s*\(|\bcPickle\s*\.\s*loads?\s*\(|\bmarshal\s*\.\s*loads\s*\(|\bshelve\s*\.\s*open\s*\(|\byaml\s*\.\s*(?:load|unsafe_load|full_load)\s*\(|\bunserialize\s*\(|\bObjectInputStream\s*\(|\breadObject\s*\(\s*\)|\bnode-serialize|\bserialize\s*\.\s*unserialize\s*\(|\bMarshal\s*\.\s*load\s*\(|\bYAML\s*\.\s*load\s*\(|BinaryFormatter\s*\(/,
    trigger: 'always',
    negate: /SafeLoader|safe_load|CSafeLoader|yaml\.safe_load|Loader\s*=\s*yaml\.Safe|safe_load_all/,
    baseSeverity: 'critical',
    title: 'Unsafe deserialization of structured data',
    description:
      'These deserializers reconstruct arbitrary object graphs and invoke constructors, `__reduce__` ' +
      'handlers or gadget chains as a side effect of parsing. A crafted payload therefore executes code ' +
      'during the parse itself - before any of your validation runs.',
    remediation:
      'Use a data-only format and parser: JSON, or `yaml.safe_load` for YAML. When object serialization is ' +
      'genuinely required, sign the payload and verify the signature before parsing, and pin an allow-list ' +
      'of deserializable classes.',
    cwe: ['CWE-502'],
  },

  // --- Cross-site scripting sinks -----------------------------------------
  {
    id: 'html-injection-sink',
    pattern:
      /\.\s*innerHTML\s*=|\.\s*outerHTML\s*=|dangerouslySetInnerHTML|\bdocument\s*\.\s*write(?:ln)?\s*\(|\bv-html\b|\.\s*insertAdjacentHTML\s*\(/,
    trigger: 'onTaint',
    baseSeverity: 'high',
    title: 'Untrusted value written into an HTML sink',
    description:
      'Assigning to this sink parses the value as markup, so `<img src=x onerror=...>` in the data becomes ' +
      'executing script in every visitor\'s session - able to read the DOM, act as the user and exfiltrate ' +
      'their session.',
    remediation:
      'Write text, not markup: `textContent` / `innerText`, or your framework\'s default escaping ' +
      'interpolation. When rich HTML from users is a real requirement, sanitise with a maintained library ' +
      '(DOMPurify, bleach) on an allow-list basis, and add a CSP that forbids inline script as a backstop.',
    cwe: ['CWE-79'],
  },

  {
    id: 'template-escaping-disabled',
    // Scoped by language: a bare `raw(` in JavaScript is far more likely to be
    // `express.raw()` or `knex.raw()` than a markup helper.
    pattern: /\bmark_safe\s*\(|\|\s*safe\b|\bHtml\.Raw\s*\(|(?<![.\w$])raw\s*\(|\bhtml_safe\b|\braw\s*=\s*True/,
    trigger: 'onTaint',
    baseSeverity: 'high',
    languages: ['python', 'ruby', 'csharp', 'php', 'other'],
    title: 'Template auto-escaping bypassed for untrusted content',
    description:
      'These helpers exist to tell the template engine "this string is already safe HTML, render it ' +
      'verbatim". Applied to a value that came from a user, they turn the one defence that was working by ' +
      'default into an injection point.',
    remediation:
      'Remove the bypass and let the engine escape the value. If the content genuinely needs to carry ' +
      'markup, sanitise it on an allow-list basis first (bleach, sanitize) and mark only the sanitiser output as safe.',
    cwe: ['CWE-79'],
  },

  // --- SSRF ----------------------------------------------------------------
  {
    id: 'ssrf',
    pattern:
      /\b(?:fetch|axios(?:\s*\.\s*(?:get|post|put|patch|delete|request))?|got|superagent\s*\.\s*get|request|http\s*\.\s*(?:get|request)|https\s*\.\s*(?:get|request)|requests\s*\.\s*(?:get|post|put|delete|head|request)|urlopen|urlretrieve|HttpClient|WebClient|RestTemplate|curl_setopt|file_get_contents)\s*\(/,
    trigger: 'onTaint',
    baseSeverity: 'high',
    title: 'Outbound request to a URL derived from user input',
    description:
      'The destination is attacker-influenced, so the server can be aimed at addresses the client could ' +
      'not reach itself: cloud instance metadata (`169.254.169.254`, which hands out credentials), internal ' +
      'admin panels, databases on the private network, or `file://` and `gopher://` schemes. Redirects and ' +
      'DNS names resolving to private ranges defeat naive string checks.',
    remediation:
      'Validate against an allow-list of permitted hosts rather than blocking known-bad ones. Parse the ' +
      'URL, require `https`, resolve the hostname and reject private, loopback and link-local addresses - ' +
      'then pin that resolved address for the request itself so DNS cannot change under you. Disable ' +
      'automatic redirect following, or re-validate every hop.',
    cwe: ['CWE-918'],
  },

  // --- Weak cryptography ---------------------------------------------------
  {
    id: 'weak-cipher',
    pattern:
      /\b(?:DES|3DES|DESede|RC2|RC4|ARCFOUR|Blowfish)\b|createCipher\s*\(|\bAES\/ECB|["']aes-\d+-ecb["']|MODE_ECB|\bECB\b|PKCS1Padding|\bNULL\b\s*cipher/,
    trigger: 'always',
    baseSeverity: 'medium',
    title: 'Weak or misused cipher',
    description:
      'DES and RC4 are broken and their key sizes are brute-forceable. ECB mode encrypts identical ' +
      'plaintext blocks to identical ciphertext blocks, so structure in the data leaks straight through. ' +
      "Node's `createCipher` derives a key from a password with a single MD5 pass and a fixed IV.",
    remediation:
      'Use an AEAD construction - AES-256-GCM or ChaCha20-Poly1305 - with a random per-message nonce and ' +
      '`createCipheriv`. AEAD gives you integrity as well as confidentiality, which unauthenticated modes ' +
      'do not.',
    cwe: ['CWE-327', 'CWE-326'],
  },
  {
    id: 'weak-hash-signature',
    pattern: /\b(?:md5|MD5|sha1|SHA-?1)\b/,
    trigger: 'onTaint',
    baseSeverity: 'medium',
    title: 'Broken hash function used where collision resistance matters',
    description:
      'Practical collisions exist for both MD5 and SHA-1, so neither can be relied on for signatures, ' +
      'integrity checks or deduplication of security-relevant data.',
    remediation:
      'Use SHA-256 or better for integrity, and HMAC-SHA-256 when a shared key is involved. MD5 remains ' +
      'acceptable only for non-security uses such as cache keys - say so in a comment when that is the case.',
    cwe: ['CWE-328'],
  },

  // --- XXE -----------------------------------------------------------------
  {
    id: 'xxe',
    pattern:
      /\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|SAXReader|XmlTextReader)\b|\betree\s*\.\s*(?:parse|fromstring)\s*\(|\bxml\s*\.\s*dom\s*\.\s*minidom\s*\.\s*parse|\bnoent\s*:\s*true|\bresolve_entities\s*=\s*True|\bDTDProcessing\s*=\s*DtdProcessing\.Parse/,
    trigger: 'always',
    negate:
      /disallow-doctype-decl|FEATURE_SECURE_PROCESSING|setExpandEntityReferences\s*\(\s*false|resolve_entities\s*=\s*False|no_network\s*=\s*True|defusedxml|XMLConstants\.FEATURE_SECURE_PROCESSING|DtdProcessing\.Prohibit/,
    baseSeverity: 'high',
    title: 'XML parser created without external entities disabled',
    description:
      'By default these parsers resolve DOCTYPE declarations and external entities, so an uploaded ' +
      'document can read local files (`SYSTEM "file:///etc/passwd"`), make the server issue requests on the ' +
      "attacker's behalf, or exhaust memory through entity expansion.",
    remediation:
      'Disable DTDs entirely: `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` ' +
      'in Java, `defusedxml` in Python, `noent: false` with `nonet: true` for libxml bindings, ' +
      '`DtdProcessing.Prohibit` in .NET.',
    cwe: ['CWE-611'],
  },

  // --- Archive and filesystem ---------------------------------------------
  {
    id: 'zip-slip',
    pattern: /\b(?:extractall|extract|unzip|ZipFile|TarFile|tarfile\s*\.\s*open|ZipInputStream|AdmZip)\b/,
    trigger: 'onTaint',
    baseSeverity: 'high',
    title: 'Archive extracted without validating member paths',
    description:
      'Archive entries may contain `../` sequences or absolute paths. Extracting them blindly writes ' +
      'outside the target directory, which can overwrite application code, an SSH key or a systemd unit.',
    remediation:
      'Resolve each entry against the destination and skip anything that escapes it. Python 3.12+ offers ' +
      '`extractall(filter="data")`. Reject symlink and device entries, and cap the total uncompressed size ' +
      'to bound decompression bombs.',
    cwe: ['CWE-22', 'CWE-409'],
  },
  {
    id: 'world-writable-permissions',
    pattern: /\bchmod\s*\(?\s*["']?0?7{2,3}["']?|\bos\s*\.\s*chmod\s*\([^,]+,\s*0o?7{2,3}\)|\b0666\b|\bumask\s*\(\s*0\s*\)/,
    trigger: 'always',
    baseSeverity: 'medium',
    title: 'World-writable file permissions',
    description:
      'Any local user or process can modify the file. For a script, config or credential file that is a ' +
      'local privilege-escalation primitive.',
    remediation:
      'Grant the narrowest mode that works - `0600` for secrets, `0644` for read-only data, `0755` for ' +
      'executables - and rely on ownership rather than broad modes.',
    cwe: ['CWE-732'],
  },
  {
    id: 'insecure-temp-file',
    pattern: /\b(?:tmpnam|mktemp|tempnam)\s*\(|["']\/tmp\/[A-Za-z0-9_.\-]+["']/,
    trigger: 'always',
    baseSeverity: 'low',
    title: 'Predictable temporary file path',
    description:
      'A fixed or guessable path in a shared directory lets a local attacker pre-create the path as a ' +
      'symlink and redirect the write, or race the check-then-open window.',
    remediation:
      'Use an API that creates the file atomically with exclusive permissions: `fs.mkdtemp`, ' +
      '`tempfile.NamedTemporaryFile`, `os.CreateTemp`.',
    cwe: ['CWE-377'],
  },

  // --- Prototype pollution -------------------------------------------------
  {
    id: 'prototype-pollution-sink',
    pattern:
      /\b(?:merge|deepMerge|extend|deepExtend|assignDeep|setValue|set)\s*\(\s*[^,)]*,\s*(?:req|request)\s*\.\s*(?:body|query|params)|\[\s*(?:key|prop|name|field|path)\s*\]\s*=/,
    trigger: 'onTaint',
    baseSeverity: 'medium',
    title: 'Recursive merge or dynamic property write from untrusted data',
    description:
      'A key of `__proto__`, `constructor` or `prototype` in the incoming object walks up to ' +
      '`Object.prototype` and changes behaviour for every object in the process - which can flip an ' +
      '`isAdmin` check, poison a template lookup, or crash the service.',
    remediation:
      'Reject `__proto__`, `constructor` and `prototype` keys before merging, build targets with ' +
      '`Object.create(null)`, or use `structuredClone` / a schema validator that only copies known fields. ' +
      'Prefer `Map` over plain objects for untrusted keys.',
    cwe: ['CWE-1321'],
  },

  // --- Debug exposure ------------------------------------------------------
  {
    id: 'debug-mode-enabled',
    pattern: /\bDEBUG\s*=\s*True\b|\bapp\s*\.\s*run\s*\([^)]*debug\s*=\s*True|\bapp\s*\.\s*debug\s*=\s*true\b|\bexpress\s*\.\s*errorHandler|\bshowStack\s*:\s*true/,
    trigger: 'always',
    baseSeverity: 'medium',
    title: 'Debug mode enabled',
    description:
      'Debug handlers render stack traces, local variable values, settings and sometimes an interactive ' +
      'console into the HTTP response. On a reachable deployment that is a detailed map of the ' +
      "application's internals, and in Flask's case a remote code execution console.",
    remediation:
      'Drive this from configuration with a safe default (off), and make the production entrypoint assert ' +
      'that it is off at startup. Return an opaque error ID to clients and keep the detail in server logs.',
    cwe: ['CWE-489', 'CWE-215'],
  },
];

const CWE_REGEX_DOS = ['CWE-1333'];

/** Nested quantifiers - the classic catastrophic-backtracking shape. */
const REDOS_SHAPE = /\((?:[^()|]*[+*]\)?)+\)[+*]|\((?:[^()]*\|[^()]*)\)[+*][+*]|\[[^\]]+\][+*][+*]/;

export const dangerousApiRule: Rule = {
  id: 'dangerous-api',
  category: 'dangerous-api',
  description:
    'Flags high-risk APIs - dynamic evaluation, shell execution, unsafe deserialization, HTML sinks, SSRF, weak crypto, XXE and archive extraction - weighted by whether untrusted input can reach them.',
  languages: ['*'],
  skipLanguages: ['documentation'],

  check(target: ScanTarget): Finding[] {
    const findings: Finding[] = [];
    const taint = buildTaintMap(target);
    const candidateLines =
      target.changedLines ?? new Set(target.lines.map((_, index) => index + 1));

    for (const lineNumber of [...candidateLines].sort((a, b) => a - b)) {
      const raw = target.lines[lineNumber - 1];
      if (raw === undefined || raw.trim().length === 0 || isCommentLine(raw)) continue;
      const structural = blankStringLiterals(raw);

      for (const sink of SINKS) {
        if (sink.languages && !sink.languages.includes(target.language)) continue;
        if (!sink.pattern.test(raw)) continue;
        if (sink.negate && sink.negate.test(enclosingBlock(target, lineNumber, 6))) continue;

        const strength = taintStrength(raw, taint);
        if (sink.trigger === 'onTaint' && strength === 'none') continue;
        // For `always` sinks in an import or type position there is no call.
        if (sink.trigger === 'always' && /^\s*(?:import|from|using|require|#include)\b/.test(raw)) continue;

        findings.push(
          makeFinding(target, 'dangerous-api', {
            ruleId: `dangerous-api/${sink.id}`,
            severity: escalate(sink.baseSeverity, strength),
            confidence: confidenceFor(sink.trigger, strength),
            title: sink.title,
            description: `${sink.description} ${taintNote(strength)}`,
            remediation: sink.remediation,
            line: lineNumber,
            evidence: raw,
            cwe: sink.cwe,
          }),
        );
      }

      // Regular expressions assembled from untrusted input.
      if (
        /new\s+RegExp\s*\(|re\s*\.\s*compile\s*\(|Pattern\s*\.\s*compile\s*\(/.test(structural) &&
        taintStrength(raw, taint) !== 'none'
      ) {
        findings.push(
          makeFinding(target, 'dangerous-api', {
            ruleId: 'dangerous-api/regex-from-user-input',
            severity: 'medium',
            confidence: 'medium',
            title: 'Regular expression compiled from untrusted input',
            description:
              'An attacker who controls the pattern controls how long matching takes. A short input such ' +
              'as `(a+)+$` against a modest string pins a CPU core for minutes, and on a single-threaded ' +
              'runtime that stalls every other request - a denial of service from one HTTP call.',
            remediation:
              'Do not compile user-supplied patterns. Offer a fixed set of searches, or escape the input ' +
              'and use it as a literal. If dynamic patterns are a product feature, run them in a worker ' +
              'with a hard timeout, or use a linear-time engine (RE2).',
            line: lineNumber,
            evidence: raw,
            cwe: CWE_REGEX_DOS,
          }),
        );
      }

      // A hardcoded regex with a catastrophic shape, applied to request data.
      if (REDOS_SHAPE.test(raw) && /\.\s*(?:test|match|exec|search|replace)\s*\(/.test(raw)) {
        const strength = taintStrength(raw, taint);
        if (strength !== 'none') {
          findings.push(
            makeFinding(target, 'dangerous-api', {
              ruleId: 'dangerous-api/catastrophic-backtracking',
              severity: 'medium',
              confidence: 'low',
              title: 'Regex with nested quantifiers applied to untrusted input',
              description:
                'Nested quantifiers such as `(a+)+` or `(\\d|\\s)*` give the backtracking engine ' +
                'exponentially many ways to fail a match. A crafted input turns this line into an ' +
                'unbounded CPU loop.',
              remediation:
                'Rewrite the pattern to remove the ambiguity - anchor it, use a possessive or atomic ' +
                'group, or replace the nested quantifier with a character class. Cap input length before ' +
                'matching as a cheap mitigation.',
              line: lineNumber,
              evidence: raw,
              cwe: CWE_REGEX_DOS,
            }),
          );
        }
      }
    }

    return findings;
  },
};

function escalate(base: Finding['severity'], strength: TaintStrength): Finding['severity'] {
  if (strength === 'direct' || strength === 'variable') {
    if (base === 'high') return 'critical';
    if (base === 'medium') return 'high';
    if (base === 'low') return 'medium';
  }
  return base;
}

function confidenceFor(trigger: Sink['trigger'], strength: TaintStrength): Finding['confidence'] {
  if (trigger === 'always') return strength === 'none' ? 'medium' : 'high';
  if (strength === 'direct') return 'high';
  if (strength === 'variable') return 'medium';
  return 'low';
}

function taintNote(strength: TaintStrength): string {
  switch (strength) {
    case 'direct':
      return 'The argument on this line is read directly from the request.';
    case 'variable':
      return 'One of the values on this line was traced back to request data earlier in the file.';
    case 'naming':
      return 'The identifiers here suggest external data; confirm the source.';
    default:
      return 'Confirm that no caller-controlled value can reach this argument.';
  }
}
