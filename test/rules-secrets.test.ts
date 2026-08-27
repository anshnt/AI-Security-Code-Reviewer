import { describe, expect, it } from 'vitest';
import { secretsRule } from '../src/analysis/rules/secrets';
import { expectRule, run } from './helpers';

/**
 * Credential-shaped fixtures are assembled at runtime rather than written as
 * literals.
 *
 * The strings below are invented, but they are invented to match real provider
 * formats - that is the whole point of the test. A literal that matches a
 * provider format will be flagged by every other scanner pointed at this
 * repository, and by GitHub's own push protection, which is a reasonable thing
 * for those tools to do. Joining the parts at runtime keeps the fixture exact
 * where the scanner sees it and keeps the source file free of anything that
 * looks like a live key.
 */
function assemble(...parts: string[]): string {
  return parts.join('');
}

describe('secrets', () => {
  it('detects an AWS access key ID', () => {
    const findings = run(secretsRule, 'src/aws.ts', 'const key = "AKIAIOSFODNN7EXAMPLE";');
    const finding = expectRule(findings, 'secrets/aws-access-key-id');
    expect(finding.severity).toBe('critical');
    expect(finding.confidence).toBe('high');
  });

  it('detects a GitHub personal access token', () => {
    const findings = run(
      secretsRule,
      'scripts/deploy.sh',
      `export TOKEN=${assemble('ghp', '_', 'A1b2C3d4E5f6', 'G7h8I9j0K1l2', 'M3n4O5p6Q7r8')}`,
    );
    expectRule(findings, 'secrets/github-token');
  });

  it('detects a private key block', () => {
    const findings = run(secretsRule, 'config/key.txt', '-----BEGIN RSA PRIVATE KEY-----');
    expectRule(findings, 'secrets/private-key');
  });

  it('detects a connection string with an inline password', () => {
    const findings = run(
      secretsRule,
      'src/db.ts',
      'const url = "postgres://svc_user:hunter2SuperLong@db.internal:5432/app";',
    );
    expectRule(findings, 'secrets/database-url-with-password');
  });

  it('detects a Stripe live secret key', () => {
    const findings = run(
      secretsRule,
      'src/pay.ts',
      `const stripe = require("stripe")("${assemble('sk', '_', 'live', '_', '51H8xKzJq7bVn4cRt9wLmPqXs')}");`,
    );
    expectRule(findings, 'secrets/stripe-secret-key');
  });

  it('never echoes the full credential back in the snippet', () => {
    const findings = run(secretsRule, 'src/aws.ts', 'const key = "AKIAIOSFODNN7EXAMPLE";');
    expect(findings[0]!.snippet).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(findings[0]!.snippet).toContain('AKIA');
  });

  it('flags a high-entropy hardcoded credential', () => {
    const findings = run(
      secretsRule,
      'src/config.ts',
      'const apiSecret = "Zq7#vR2pLm9$Kd4Xw8Tb6Nj1";',
    );
    const finding = expectRule(findings, 'secrets/hardcoded-credential');
    expect(finding.severity).toBe('high');
  });

  it('ignores values read from the environment', () => {
    const findings = run(secretsRule, 'src/config.ts', 'const apiKey = process.env.API_KEY;');
    expect(findings).toEqual([]);
  });

  it('ignores documented placeholders', () => {
    const source = [
      'const password = "your-password-here";',
      'const token = "xxxxxxxxxxxx";',
      'const secret = "changeme";',
      'const apiKey = "<YOUR_API_KEY>";',
      'const clientSecret = "${CLIENT_SECRET}";',
    ].join('\n');
    expect(run(secretsRule, 'src/config.ts', source)).toEqual([]);
  });

  it('ignores low-entropy prose assigned to a credential name', () => {
    const findings = run(secretsRule, 'src/config.ts', 'const passwordLabel = "Enter password";');
    expect(findings).toEqual([]);
  });

  it('flags a committed .env file', () => {
    const findings = run(secretsRule, '.env', 'DATABASE_URL=postgres://localhost/app');
    expectRule(findings, 'secrets/sensitive-file-committed');
  });

  it('allows .env.example', () => {
    const findings = run(secretsRule, '.env.example', 'DATABASE_URL=');
    expect(findings.filter((f) => f.ruleId === 'secrets/sensitive-file-committed')).toEqual([]);
  });

  it('reports each distinct credential once', () => {
    const source = [
      'const a = "AKIAIOSFODNN7EXAMPLE";',
      'const b = "AKIAIOSFODNN7EXAMPLE";',
    ].join('\n');
    const findings = run(secretsRule, 'src/aws.ts', source).filter(
      (f) => f.ruleId === 'secrets/aws-access-key-id',
    );
    expect(findings).toHaveLength(1);
  });
});
