import { isCommentLine, makeFinding, shannonEntropy } from '../source';
import type { Finding, Rule, ScanTarget } from '../types';

/**
 * Credential detection.
 *
 * Two tiers, because they have opposite error profiles:
 *
 *   Provider patterns are near-zero false positive - `AKIA` followed by 16
 *   uppercase characters is an AWS key ID and nothing else. These are reported
 *   at high confidence even in test files, because a committed live key is
 *   still live.
 *
 *   Generic assignments (`password = "..."`) are the opposite: common, and
 *   usually harmless. Those go through a placeholder filter and an entropy gate
 *   before they are allowed to surface.
 */

interface ProviderPattern {
  id: string;
  name: string;
  pattern: RegExp;
  severity: Finding['severity'];
  /** Revocation/rotation guidance specific to the provider. */
  rotate: string;
}

const PROVIDER_PATTERNS: ProviderPattern[] = [
  {
    id: 'aws-access-key-id',
    name: 'AWS access key ID',
    pattern: /\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/,
    severity: 'critical',
    rotate: 'Deactivate the key in IAM, then delete it, and check CloudTrail for use you did not authorise.',
  },
  {
    id: 'aws-secret-access-key',
    name: 'AWS secret access key',
    pattern: /\baws_?secret_?access_?key\W{0,4}['"]?([A-Za-z0-9/+=]{40})['"]?/i,
    severity: 'critical',
    rotate: 'Deactivate and delete the key pair in IAM, then review CloudTrail.',
  },
  {
    id: 'github-token',
    name: 'GitHub token',
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/,
    severity: 'critical',
    rotate: 'Revoke it under Settings > Developer settings > Personal access tokens.',
  },
  {
    id: 'slack-token',
    name: 'Slack token',
    pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/,
    severity: 'high',
    rotate: 'Rotate the token in the Slack app configuration and reinstall the app.',
  },
  {
    id: 'slack-webhook',
    name: 'Slack incoming webhook',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]+\/B[A-Za-z0-9_]+\/[A-Za-z0-9_]+/,
    severity: 'medium',
    rotate: 'Delete the webhook in the Slack app configuration and create a new one.',
  },
  {
    id: 'stripe-secret-key',
    name: 'Stripe live secret key',
    pattern: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b/,
    severity: 'critical',
    rotate: 'Roll the key in the Stripe dashboard immediately and audit recent API activity.',
  },
  {
    id: 'google-api-key',
    name: 'Google API key',
    pattern: /\bAIza[A-Za-z0-9_\-]{35}\b/,
    severity: 'high',
    rotate: 'Delete the key in the Google Cloud console; add API and referrer restrictions to its replacement.',
  },
  {
    id: 'gcp-service-account',
    name: 'GCP service account private key',
    pattern: /"type"\s*:\s*"service_account"|"private_key_id"\s*:\s*"[a-f0-9]{40}"/,
    severity: 'critical',
    rotate: 'Delete the service account key in IAM and issue a new one; prefer workload identity federation.',
  },
  {
    id: 'openai-api-key',
    name: 'OpenAI API key',
    pattern: /\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b/,
    severity: 'high',
    rotate: 'Revoke the key in the provider dashboard and issue a replacement.',
  },
  {
    id: 'anthropic-api-key',
    name: 'Anthropic API key',
    pattern: /\bsk-ant-[A-Za-z0-9_\-]{24,}\b/,
    severity: 'high',
    rotate: 'Revoke the key in the provider console and issue a replacement.',
  },
  {
    id: 'sendgrid-api-key',
    name: 'SendGrid API key',
    pattern: /\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b/,
    severity: 'high',
    rotate: 'Delete the key in SendGrid > Settings > API Keys.',
  },
  {
    id: 'twilio-api-key',
    name: 'Twilio credential',
    pattern: /\bSK[a-f0-9]{32}\b|\bAC[a-f0-9]{32}\b/,
    severity: 'high',
    rotate: 'Rotate the auth token or delete the API key in the Twilio console.',
  },
  {
    id: 'npm-token',
    name: 'npm access token',
    pattern: /\bnpm_[A-Za-z0-9]{36}\b/,
    severity: 'high',
    rotate: 'Revoke it with `npm token revoke` and publish a replacement token as a CI secret.',
  },
  {
    id: 'private-key',
    name: 'Private key block',
    pattern: /-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/,
    severity: 'critical',
    rotate: 'Treat the key as compromised: generate a new pair and re-issue any certificate signed with it.',
  },
  {
    id: 'jwt',
    name: 'Signed JWT',
    pattern: /\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{10,}\b/,
    severity: 'medium',
    rotate: 'If the token is still valid, rotate the signing secret so it and its siblings stop verifying.',
  },
  {
    id: 'database-url-with-password',
    name: 'Connection string with inline password',
    pattern:
      /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql|clickhouse):\/\/[^:\s'"@/]+:([^@\s'"]{4,})@/i,
    severity: 'critical',
    rotate: 'Rotate the database user password and move the URL into a secret store.',
  },
];

/** Assignments to obviously credential-shaped names. */
const GENERIC_ASSIGNMENT =
  /\b((?:[A-Za-z0-9_]*)?(?:passwd|password|secret|token|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|client[_-]?secret|private[_-]?key|encryption[_-]?key|signing[_-]?key|credential|bearer)(?:[A-Za-z0-9_]*)?)\s*[:=]\s*(?:=\s*)?(["'`])([^"'`\n]{6,})\2/i;

/** Values that look like credentials but are documentation, not secrets. */
const PLACEHOLDER =
  /^(?:x{3,}|y{3,}|\*{3,}|\.{3,}|-{3,}|<[^>]*>|\{\{?[^}]*\}?\}|\$\{[^}]*\}|%[a-z_]+%|:[a-z_]+|null|none|nil|true|false|undefined|empty|todo|tbd|n\/?a)$/i;
const PLACEHOLDER_WORDS =
  /\b(?:your|my|some|example|sample|dummy|fake|placeholder|redacted|removed|changeme|change_me|replace|insert|here|test|testing|localhost|foo|bar|baz|password|secret|token|apikey|api_key|value|xxxxx|abcdef|123456|s3cret|hunter2|dev|local|default)\b/i;
/** References to a secret store rather than a secret. */
const INDIRECTION =
  /process\.env|os\.environ|os\.getenv|ENV\[|System\.getenv|Deno\.env|secrets\.|vault|ssm|parameterstore|keyvault|getSecret|fromEnv|config\.get|\$\{\{|\{\{\s*\w+\s*\}\}/i;

const CWE = ['CWE-798', 'CWE-540'];

/** Filenames that exist to hold real credentials. */
const SENSITIVE_FILE =
  /(^|\/)(?:\.env(?:\.[a-z]+)?|\.npmrc|\.pypirc|\.netrc|id_rsa|id_ed25519|id_dsa|credentials|\.pgpass|\.htpasswd|service-account.*\.json|.*\.pem|.*\.pfx|.*\.p12|.*\.keystore|.*\.jks)$/i;

export const secretsRule: Rule = {
  id: 'secrets',
  category: 'secrets',
  description:
    'Detects credentials committed to the repository, using provider-specific token formats plus an entropy-gated generic check.',
  languages: ['*'],

  check(target: ScanTarget): Finding[] {
    const findings: Finding[] = [];
    const seen = new Set<string>();

    if (SENSITIVE_FILE.test(target.filePath) && target.status !== 'removed') {
      // `.env.example` is the documented exception - it exists to hold placeholders.
      if (!/\.(?:example|sample|template|dist)$/i.test(target.filePath)) {
        findings.push(
          makeFinding(target, 'secrets', {
            ruleId: 'secrets/sensitive-file-committed',
            severity: 'high',
            confidence: 'high',
            title: `Credential-bearing file \`${target.filePath}\` added to version control`,
            description:
              'Files of this kind exist to hold real credentials. Once committed, the values stay ' +
              'in the git history even after a later deletion, and anyone with clone access can read them.',
            remediation:
              'Remove the file from the index (`git rm --cached`), add the path to `.gitignore`, ' +
              'commit a `.example` variant with placeholder values, and rotate anything the file contained. ' +
              'Purging the history needs a rewrite (`git filter-repo`) plus a force-push.',
            line: 1,
            evidence: target.filePath,
            cwe: CWE,
          }),
        );
      }
    }

    const candidateLines =
      target.changedLines ?? new Set(target.lines.map((_, index) => index + 1));

    for (const lineNumber of [...candidateLines].sort((a, b) => a - b)) {
      const raw = target.lines[lineNumber - 1];
      if (raw === undefined || raw.trim().length === 0) continue;
      // A very long line is almost always minified or encoded data.
      if (raw.length > 1000) continue;

      for (const provider of PROVIDER_PATTERNS) {
        const match = provider.pattern.exec(raw);
        if (!match) continue;
        const value = match[1] ?? match[0];
        if (isPlaceholderValue(value)) continue;
        const key = `${provider.id}:${value}`;
        if (seen.has(key)) continue;
        seen.add(key);

        findings.push(
          makeFinding(target, 'secrets', {
            ruleId: `secrets/${provider.id}`,
            severity: provider.severity,
            confidence: 'high',
            title: `${provider.name} committed to the repository`,
            description:
              `This line contains a value matching the ${provider.name} format. Committed credentials must ` +
              'be treated as compromised: the value is in every clone, every fork and every CI cache that ' +
              'has ever fetched this branch, and removing it in a later commit does not remove it from history.',
            remediation:
              `${provider.rotate} Then read the value from the environment or a secret manager at runtime, ` +
              'and add a pre-commit secret scan so the next one is caught before it lands.',
            line: lineNumber,
            evidence: redact(raw, value),
            cwe: CWE,
          }),
        );
      }

      if (isCommentLine(raw)) continue;

      const generic = GENERIC_ASSIGNMENT.exec(raw);
      if (generic) {
        const name = generic[1]!;
        const value = generic[3]!;
        if (
          !isPlaceholderValue(value) &&
          !INDIRECTION.test(raw) &&
          shannonEntropy(value) >= 3.0 &&
          value.length >= 8 &&
          // Reject prose and paths, which score respectably on entropy.
          !/\s/.test(value) &&
          !/^(?:https?|file|\.{0,2})?\/[^\s]*$/.test(value)
        ) {
          const key = `generic:${value}`;
          if (!seen.has(key)) {
            seen.add(key);
            findings.push(
              makeFinding(target, 'secrets', {
                ruleId: 'secrets/hardcoded-credential',
                severity: 'high',
                confidence: shannonEntropy(value) >= 4.0 ? 'high' : 'medium',
                title: `Hardcoded value assigned to \`${name}\``,
                description:
                  `\`${name}\` is assigned a high-entropy literal (${shannonEntropy(value).toFixed(1)} bits per ` +
                  'character), which is what a real credential looks like. A hardcoded secret cannot be rotated ' +
                  'without a code change and a deploy, and it is readable by everyone with repository access.',
                remediation:
                  'Move the value to an environment variable or secret manager and read it at startup. ' +
                  'Fail fast when it is missing rather than falling back to a baked-in default. ' +
                  'If this really is a non-secret, rename it or add `// security-review-ignore secrets` with a reason.',
                line: lineNumber,
                evidence: redact(raw, value),
                cwe: CWE,
              }),
            );
          }
        }
      }
    }

    return findings;
  },
};

function isPlaceholderValue(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length === 0) return true;
  if (PLACEHOLDER.test(trimmed)) return true;
  if (PLACEHOLDER_WORDS.test(trimmed)) return true;
  // A single repeated character, or an obvious keyboard run.
  if (/^(.)\1+$/.test(trimmed)) return true;
  if (/^(?:abc|123|qwerty|password)/i.test(trimmed)) return true;
  return false;
}

/** Never echo a full credential back into a PR comment or the database. */
function redact(line: string, value: string): string {
  if (value.length <= 8) return line.replace(value, '***');
  return line.replace(value, `${value.slice(0, 4)}...${'*'.repeat(6)}`);
}
