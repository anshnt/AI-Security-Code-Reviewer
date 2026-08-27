import { describe, expect, it } from 'vitest';
import { authenticationRule } from '../src/analysis/rules/authentication';
import { authorizationRule } from '../src/analysis/rules/authorization';
import { expectRule, run } from './helpers';

describe('authentication', () => {
  it('flags a JWT decoded without verification', () => {
    const findings = run(
      authenticationRule,
      'src/auth.ts',
      `
function currentUser(req) {
  const claims = jwt.decode(req.headers.authorization);
  return claims.sub;
}
`,
    );
    const finding = expectRule(findings, 'authentication/jwt-decode-without-verify');
    expect(finding.severity).toBe('critical');
  });

  it('does not flag decode when verify is used nearby', () => {
    const findings = run(
      authenticationRule,
      'src/auth.ts',
      `
function currentUser(req) {
  const claims = jwt.verify(req.headers.authorization, SECRET, { algorithms: ['RS256'] });
  const preview = jwt.decode(req.headers.authorization);
  return claims.sub;
}
`,
    );
    expect(findings.filter((f) => f.ruleId === 'authentication/jwt-decode-without-verify')).toEqual([]);
  });

  it('flags the none algorithm', () => {
    const findings = run(
      authenticationRule,
      'src/auth.ts',
      "const options = { algorithms: ['none'] };",
    );
    expectRule(findings, 'authentication/jwt-algorithm-none');
  });

  it('flags disabled expiry validation', () => {
    const findings = run(authenticationRule, 'src/auth.ts', 'jwt.verify(t, k, { ignoreExpiration: true });');
    expectRule(findings, 'authentication/jwt-expiry-ignored');
  });

  it('flags a fast hash used on a password', () => {
    const findings = run(
      authenticationRule,
      'src/users.ts',
      `
function storePassword(password) {
  const hashed = crypto.createHash('sha256').update(password).digest('hex');
  return hashed;
}
`,
    );
    expectRule(findings, 'authentication/weak-password-hash');
  });

  it('flags disabled TLS verification', () => {
    const findings = run(
      authenticationRule,
      'src/client.ts',
      'const agent = new https.Agent({ rejectUnauthorized: false });',
    );
    const finding = expectRule(findings, 'authentication/tls-verification-disabled');
    expect(finding.cwe).toContain('CWE-295');
  });

  it('flags verify=False in Python', () => {
    const findings = run(authenticationRule, 'app/client.py', 'r = requests.get(url, verify=False)');
    expectRule(findings, 'authentication/tls-verification-disabled');
  });

  it('flags a session cookie without HttpOnly', () => {
    const findings = run(
      authenticationRule,
      'src/session.ts',
      "app.use(session({ secret: s, cookie: { httpOnly: false } }));",
    );
    expectRule(findings, 'authentication/insecure-cookie-flags');
  });

  it('flags a non-constant-time signature comparison', () => {
    const findings = run(
      authenticationRule,
      'src/webhook.ts',
      `
function check(req) {
  const signature = req.get('x-signature');
  if (signature === expected) return true;
  return false;
}
`,
    );
    expectRule(findings, 'authentication/non-constant-time-comparison');
  });

  it('does not flag a timing-safe comparison', () => {
    const findings = run(
      authenticationRule,
      'src/webhook.ts',
      `
function check(signature, expected) {
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}
`,
    );
    expect(findings.filter((f) => f.ruleId === 'authentication/non-constant-time-comparison')).toEqual([]);
  });

  it('flags Math.random used to build a token', () => {
    const findings = run(
      authenticationRule,
      'src/tokens.ts',
      'const resetToken = Math.random().toString(36).slice(2);',
    );
    expectRule(findings, 'authentication/insecure-random-for-secret');
  });

  it('does not flag Math.random outside a security context', () => {
    const findings = run(
      authenticationRule,
      'src/animation.ts',
      'const jitter = Math.random() * 40;',
    );
    expect(findings).toEqual([]);
  });

  it('flags an environment-gated auth bypass', () => {
    const findings = run(
      authenticationRule,
      'src/middleware/auth.ts',
      `
export function requireAuth(req, res, next) {
  if (process.env.NODE_ENV !== 'production') return next();
  if (!req.session.userId) return res.status(401).end();
  next();
}
`,
    );
    const finding = expectRule(findings, 'authentication/environment-gated-bypass');
    expect(finding.severity).toBe('critical');
  });
});

describe('authorization', () => {
  it('flags a lookup by client-supplied id with no ownership predicate', () => {
    const findings = run(
      authorizationRule,
      'src/invoices.ts',
      `
router.get('/invoices/:id', async (req, res) => {
  const invoice = await Invoice.findByPk(req.params.id);
  res.json(invoice);
});
`,
    );
    const finding = expectRule(findings, 'authorization/missing-ownership-check');
    expect(finding.cwe).toContain('CWE-639');
  });

  it('does not flag a lookup scoped to the caller', () => {
    const findings = run(
      authorizationRule,
      'src/invoices.ts',
      `
router.get('/invoices/:id', async (req, res) => {
  const invoice = await Invoice.findOne({ where: { id: req.params.id, userId: req.user.id } });
  res.json(invoice);
});
`,
    );
    expect(findings.filter((f) => f.ruleId === 'authorization/missing-ownership-check')).toEqual([]);
  });

  it('flags mass assignment from the request body', () => {
    const findings = run(
      authorizationRule,
      'src/profile.ts',
      'await User.update(req.body);',
    );
    expectRule(findings, 'authorization/mass-assignment');
  });

  it('flags a spread of the request body', () => {
    const findings = run(
      authorizationRule,
      'src/profile.ts',
      'const user = await User.create({ ...req.body });',
    );
    expectRule(findings, 'authorization/mass-assignment');
  });

  it('flags a role read from the request', () => {
    const findings = run(
      authorizationRule,
      'src/admin.ts',
      "if (req.body.role === 'admin') { grantAccess(); }",
    );
    const finding = expectRule(findings, 'authorization/client-supplied-role');
    expect(finding.severity).toBe('critical');
  });

  it('flags a state-changing route with no auth middleware', () => {
    const findings = run(
      authorizationRule,
      'src/routes.ts',
      "router.delete('/accounts/:id', deleteAccount);",
    );
    expectRule(findings, 'authorization/unprotected-state-changing-route');
  });

  it('does not flag a route that names auth middleware', () => {
    const findings = run(
      authorizationRule,
      'src/routes.ts',
      "router.delete('/accounts/:id', requireAuth, deleteAccount);",
    );
    expect(
      findings.filter((f) => f.ruleId === 'authorization/unprotected-state-changing-route'),
    ).toEqual([]);
  });

  it('does not flag a webhook route', () => {
    const findings = run(
      authorizationRule,
      'src/routes.ts',
      "router.post('/webhook/stripe', handleStripeWebhook);",
    );
    expect(
      findings.filter((f) => f.ruleId === 'authorization/unprotected-state-changing-route'),
    ).toEqual([]);
  });

  it('flags a public object ACL', () => {
    const findings = run(
      authorizationRule,
      'src/upload.ts',
      "await s3.putObject({ Bucket: b, Key: k, Body: body, ACL: 'public-read' });",
    );
    expectRule(findings, 'authorization/public-object-acl');
  });

  it('flags a wildcard IAM principal', () => {
    const findings = run(
      authorizationRule,
      'infra/policy.json',
      '{ "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject" }',
    );
    expectRule(findings, 'authorization/iam-wildcard-principal');
  });

  it('flags a security group open to the internet', () => {
    const findings = run(
      authorizationRule,
      'infra/main.tf',
      '  cidr_blocks = ["0.0.0.0/0"]',
    );
    expectRule(findings, 'authorization/network-open-to-world');
  });

  it('flags wildcard CORS combined with credentials', () => {
    const findings = run(
      authorizationRule,
      'src/app.ts',
      "app.use(cors({ origin: '*', credentials: true }));",
    );
    expectRule(findings, 'authorization/permissive-cors-with-credentials');
  });

  it('flags path traversal in file serving', () => {
    const findings = run(
      authorizationRule,
      'src/files.ts',
      `
app.get('/download', (req, res) => {
  res.sendFile(path.join(BASE, req.query.file));
});
`,
    );
    expectRule(findings, 'authorization/path-traversal');
  });

  it('does not flag file serving that checks containment', () => {
    const findings = run(
      authorizationRule,
      'src/files.ts',
      `
app.get('/download', (req, res) => {
  const full = path.resolve(BASE, req.query.file);
  if (!full.startsWith(BASE + path.sep)) return res.status(400).end();
  res.sendFile(full);
});
`,
    );
    expect(findings.filter((f) => f.ruleId === 'authorization/path-traversal')).toEqual([]);
  });
});
