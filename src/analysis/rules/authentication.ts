// security-review-ignore-file sql-injection, authentication, dangerous-api
// This file's content is a table of patterns that *describe* unsafe code. The
// analyzers would otherwise match their own definitions, which is noise rather
// than signal - the strings here are never executed.
import { enclosingBlock, isCommentLine, makeFinding, splitIdentifiers } from '../source';
import type { Finding, Rule, ScanTarget } from '../types';

/**
 * Authentication defects.
 *
 * These are the mistakes that turn a login system into a formality: tokens
 * accepted without verification, passwords stored with a hash built for speed,
 * TLS validation switched off "temporarily", and comparisons that leak the
 * answer through timing.
 *
 * Each pattern below is paired with the specific reason it matters, because a
 * bare "insecure" verdict on an auth path is exactly the kind of comment
 * reviewers learn to ignore.
 */

interface AuthPattern {
  id: string;
  pattern: RegExp;
  /** A second pattern that, if present nearby, means the issue is already handled. */
  negate?: RegExp;
  severity: Finding['severity'];
  confidence: Finding['confidence'];
  title: string;
  description: string;
  remediation: string;
  cwe: string[];
  /** Only run against these languages; omit for language-agnostic patterns. */
  languages?: ScanTarget['language'][];
}

const PATTERNS: AuthPattern[] = [
  // --- Token verification -------------------------------------------------
  {
    id: 'jwt-decode-without-verify',
    pattern: /\b(?:jwt|jsonwebtoken|jose)?\s*\.?\s*decode\s*\(\s*(?:[^,)]*token[^,)]*|[^,)]*)\)/i,
    negate: /\bverify\s*\(|\bverifyJWT|jwtVerify|require_?auth|\.decode\s*\([^)]*verify_signature/i,
    severity: 'critical',
    confidence: 'medium',
    title: 'JWT decoded without verifying its signature',
    description:
      '`decode()` parses the token and returns its claims without checking the signature. Anyone can ' +
      'craft a token with any `sub`, `role` or `scope` they like and it will decode cleanly. If the ' +
      'returned claims are used for identity or access decisions, authentication is bypassed outright.',
    remediation:
      'Use `verify()` (or `jwtVerify`) with the expected algorithm, issuer and audience pinned, and only ' +
      'read claims from its return value. Reserve `decode()` for logging and debugging.',
    cwe: ['CWE-347', 'CWE-287'],
  },
  {
    id: 'jwt-algorithm-none',
    pattern: /\balg(?:orithms?)?\s*[:=]\s*(?:\[\s*)?["'](?:none|HS1)["']/i,
    severity: 'critical',
    confidence: 'high',
    title: 'JWT algorithm set to `none`',
    description:
      'The `none` algorithm means "this token is unsigned". Accepting it lets an attacker present a ' +
      'token with an empty signature and arbitrary claims.',
    remediation:
      'Pin an explicit allow-list of real algorithms, e.g. `{ algorithms: ["RS256"] }`, and never include ' +
      '`none`. Pinning also prevents algorithm-confusion attacks where an RS256 public key is used as an HS256 secret.',
    cwe: ['CWE-347'],
  },
  {
    id: 'jwt-expiry-ignored',
    pattern: /ignoreExpiration\s*:\s*true|verify_exp["']?\s*:\s*False|ValidateLifetime\s*=\s*false/i,
    severity: 'high',
    confidence: 'high',
    title: 'JWT expiry check disabled',
    description:
      'With expiry validation off, a token stays valid forever. Session revocation, password changes ' +
      'and offboarding all stop taking effect, and a token captured once works indefinitely.',
    remediation:
      'Remove the flag and let expiry be enforced. If long-lived access is a product requirement, ' +
      'issue short-lived access tokens plus a revocable refresh token stored server-side.',
    cwe: ['CWE-613'],
  },

  // --- Password storage ---------------------------------------------------
  {
    id: 'weak-password-hash',
    pattern:
      /(?:createHash|hashlib|MessageDigest\.getInstance|md5|sha1|sha256|sha512)\s*[(.]?\s*["']?(?:md5|sha-?1|sha-?256|sha-?512)["']?\s*\)?/i,
    severity: 'high',
    confidence: 'medium',
    title: 'Fast general-purpose hash used on a credential',
    description:
      'MD5, SHA-1 and the SHA-2 family are designed to be fast, which is exactly wrong for passwords: ' +
      'commodity hardware computes billions of them per second, so a leaked table of hashes is a leaked ' +
      'table of passwords. Salting slows an attacker down but does not change the order of magnitude.',
    remediation:
      'Use a memory-hard password hash with a tuned cost parameter - argon2id (preferred), scrypt, or ' +
      'bcrypt with cost >= 12. These libraries handle salting internally; do not roll your own.',
    cwe: ['CWE-916', 'CWE-327'],
  },
  {
    id: 'low-bcrypt-cost',
    pattern: /\b(?:bcrypt|hashpw|genSalt(?:Sync)?|gensalt|hash(?:Sync)?)\s*\([^)]*?\b(?:rounds\s*[:=]\s*)?([1-9])\b(?!\d)/,
    severity: 'medium',
    confidence: 'medium',
    title: 'bcrypt cost factor below the recommended minimum',
    description:
      'A single-digit cost factor makes each hash roughly 2^n iterations, which on current hardware is ' +
      'fast enough to brute-force a weak password in minutes.',
    remediation:
      'Raise the cost factor to at least 12 and re-benchmark: aim for roughly 250ms per hash on your ' +
      'production hardware. Re-hash on next successful login to migrate existing users.',
    cwe: ['CWE-916'],
  },
  {
    id: 'plaintext-password-comparison',
    pattern:
      /\b(?:password|passwd|pwd|pass)\b[^\n=!<>]{0,40}(?:===?|!==?|\.equals\s*\(|\bis\b|==)\s*[^\n=]{0,40}\b(?:password|passwd|pwd|pass|body|input)\b/i,
    negate: /\b(?:compare|checkpw|verify|bcrypt|argon2|scrypt|pbkdf2|timingSafeEqual|hash)\b/i,
    severity: 'critical',
    confidence: 'medium',
    title: 'Password compared as plaintext',
    description:
      'Comparing a submitted password against a stored value with `==` only works if the stored value is ' +
      'the password itself. That means the database holds plaintext credentials, and a single read - a ' +
      'backup, a log, a SQL injection elsewhere - discloses every account.',
    remediation:
      'Store only a password hash and compare with the library verifier (`bcrypt.compare`, ' +
      '`argon2.verify`), which is also constant-time. Never store or log the submitted password.',
    cwe: ['CWE-256', 'CWE-257'],
  },

  // --- Comparison and randomness -----------------------------------------
  {
    id: 'non-constant-time-comparison',
    pattern:
      /\b(?:signature|sig|hmac|mac|digest|token|otp|csrf|apiKey|api_key|secret)\b\s*(?:===?|!==?)\s*[^=\n]+|\.equals\s*\(\s*(?:signature|hmac|digest|token)\b/i,
    negate: /timingSafeEqual|compare_digest|hash_equals|constantTimeCompare|MessageDigest\.isEqual|secure_compare/i,
    severity: 'medium',
    confidence: 'medium',
    title: 'Secret compared with a short-circuiting equality check',
    description:
      'String equality returns as soon as it finds a differing byte, so the time it takes reveals how ' +
      'many leading bytes were correct. Over enough requests that is enough to recover a signature or ' +
      'token one byte at a time.',
    remediation:
      'Compare with a constant-time primitive: `crypto.timingSafeEqual` (Node), `hmac.compare_digest` ' +
      '(Python), `hash_equals` (PHP), `subtle.ConstantTimeCompare` (Go). Length-check first, since these ' +
      'throw or leak on mismatched lengths.',
    cwe: ['CWE-208'],
  },
  {
    id: 'insecure-random-for-secret',
    pattern:
      /\b(?:Math\.random\s*\(\s*\)|random\.(?:random|randint|choice|randrange|sample)\s*\(|rand\s*\(\s*\)|mt_rand\s*\(|new Random\s*\()/,
    severity: 'high',
    confidence: 'low',
    title: 'Non-cryptographic randomness on a security-sensitive path',
    description:
      'These generators are deterministic and seeded predictably. Given a couple of outputs an attacker ' +
      'can reconstruct the internal state and predict every subsequent value - so tokens, password-reset ' +
      'links, session IDs and nonces derived from them are guessable.',
    remediation:
      'Use a CSPRNG: `crypto.randomBytes` / `crypto.randomUUID` (Node), `secrets.token_urlsafe` (Python), ' +
      '`SecureRandom` (Java), `crypto/rand` (Go), `random_bytes` (PHP).',
    cwe: ['CWE-338', 'CWE-330'],
  },

  // --- Transport ----------------------------------------------------------
  {
    id: 'tls-verification-disabled',
    pattern:
      /NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*["']?0|rejectUnauthorized\s*:\s*false|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:0|false)|ServerCertificateValidationCallback\s*(?:\+?=)|check_hostname\s*=\s*False|ssl\._create_unverified_context/i,
    severity: 'high',
    confidence: 'high',
    title: 'TLS certificate verification disabled',
    description:
      'Without certificate validation, TLS still encrypts the connection but no longer proves who is on ' +
      'the other end. Anyone able to intercept the traffic can present their own certificate, read the ' +
      'credentials in flight and alter the response.',
    remediation:
      'Remove the flag. If the peer uses a private CA, add that CA to the trust store or pass it ' +
      'explicitly (`ca:` / `verify="/path/ca.pem"`) rather than disabling verification. If a self-signed ' +
      'certificate is only needed locally, gate it behind an explicit development-only configuration flag.',
    cwe: ['CWE-295'],
  },
  {
    id: 'insecure-cookie-flags',
    pattern:
      /(?:httpOnly|http_only|HttpOnly)\s*[:=]\s*(?:false|False|0)|secure\s*[:=]\s*(?:false|False|0)\b|sameSite\s*[:=]\s*["']none["']/,
    severity: 'medium',
    confidence: 'high',
    title: 'Session cookie configured without its protective flags',
    description:
      'A session cookie without `HttpOnly` is readable by any script on the page, so one XSS becomes full ' +
      'session theft. Without `Secure` it is sent over plain HTTP. `SameSite=None` re-enables ' +
      'cross-site sending, which is the precondition for CSRF.',
    remediation:
      'Set `httpOnly: true`, `secure: true` and `sameSite: "lax"` (or `"strict"` for sensitive flows). ' +
      'If a third-party embed genuinely needs `SameSite=None`, it must be paired with `Secure` and CSRF tokens.',
    cwe: ['CWE-1004', 'CWE-614'],
  },
  {
    id: 'basic-auth-hardcoded',
    pattern: /Authorization\s*[:=]\s*["'](?:Basic|Bearer)\s+[A-Za-z0-9+/=._\-]{12,}["']/i,
    severity: 'high',
    confidence: 'high',
    title: 'Authorization header with a baked-in credential',
    description:
      'The credential is part of the source, so it is shared by every deployment, cannot be rotated ' +
      'without a release, and is visible to everyone with repository access.',
    remediation:
      'Build the header at call time from a value read out of the environment or a secret manager.',
    cwe: ['CWE-798'],
  },
];

/** Auth middleware that returns early in non-production - a classic bypass. */
const ENV_BYPASS =
  /if\s*\(?\s*(?:process\.env\.NODE_ENV|NODE_ENV|env|settings\.DEBUG|app\.debug|ENVIRONMENT)\b[^)\n]{0,60}(?:!==?|==|===|!=)\s*["']?(?:production|prod|True|true)["']?\s*\)?\s*(?:\{)?\s*(?:return\s+next\s*\(\s*\)|return\s+True|next\s*\(\s*\)|return\s*;?)/i;

/**
 * Words that mark a security-sensitive region of code. Matched against the
 * identifier-split form of the source, so `resetToken` and `hashPassword` count.
 */
const AUTH_CONTEXT =
  /\b(?:auth|authenticate|authorize|authorise|login|signin|signup|register|session|token|jwt|credential|permission|guard|middleware|user|account|verify|password|passwd|pwd|passphrase|hash|hashed|crypt|secret|signature|csrf|otp|mfa|totp)\b/i;

/** Names that make a value itself security-sensitive, whatever the surroundings. */
const SENSITIVE_NAME =
  /\b(?:token|secret|nonce|salt|otp|code|key|uuid|id|reset|invite|password|passwd|pwd|signature|session|csrf|api)\b/i;

export const authenticationRule: Rule = {
  id: 'authentication',
  category: 'authentication',
  description:
    'Finds authentication weaknesses: unverified tokens, weak password hashing, disabled TLS verification, timing-unsafe secret comparison and environment-gated auth bypasses.',
  languages: ['*'],
  skipLanguages: ['documentation'],

  check(target: ScanTarget): Finding[] {
    const findings: Finding[] = [];
    const candidateLines =
      target.changedLines ?? new Set(target.lines.map((_, index) => index + 1));

    for (const lineNumber of [...candidateLines].sort((a, b) => a - b)) {
      const raw = target.lines[lineNumber - 1];
      if (raw === undefined || raw.trim().length === 0 || isCommentLine(raw)) continue;
      const block = splitIdentifiers(enclosingBlock(target, lineNumber, 12));

      for (const rule of PATTERNS) {
        if (rule.languages && !rule.languages.includes(target.language)) continue;
        if (!rule.pattern.test(raw)) continue;
        if (rule.negate && rule.negate.test(block)) continue;

        // Randomness and hashing are only interesting on a security path.
        if (
          (rule.id === 'insecure-random-for-secret' || rule.id === 'weak-password-hash') &&
          !AUTH_CONTEXT.test(block) &&
          !SENSITIVE_NAME.test(splitIdentifiers(raw))
        ) {
          continue;
        }

        findings.push(
          makeFinding(target, 'authentication', {
            ruleId: `authentication/${rule.id}`,
            severity: rule.severity,
            confidence: rule.confidence,
            title: rule.title,
            description: rule.description,
            remediation: rule.remediation,
            line: lineNumber,
            evidence: raw,
            cwe: rule.cwe,
          }),
        );
      }

      if (ENV_BYPASS.test(raw) && AUTH_CONTEXT.test(block)) {
        findings.push(
          makeFinding(target, 'authentication', {
            ruleId: 'authentication/environment-gated-bypass',
            severity: 'critical',
            confidence: 'medium',
            title: 'Authentication skipped based on an environment flag',
            description:
              'This branch short-circuits an authentication path whenever the environment is not ' +
              'production. That is one misconfigured variable away from an unauthenticated production ' +
              'deployment - and the failure is silent, because the app works perfectly either way.',
            remediation:
              'Do not branch on the environment inside auth code. Inject a real authenticator in every ' +
              'environment and use a seeded local user or a stub identity provider for development, so the ' +
              'code path under test is the code path that ships.',
            line: lineNumber,
            evidence: raw,
            cwe: ['CWE-287', 'CWE-489'],
          }),
        );
      }
    }

    return findings;
  },
};
