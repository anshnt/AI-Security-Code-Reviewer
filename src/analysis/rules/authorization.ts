// security-review-ignore-file authorization/iam-wildcard-principal, authorization/iam-wildcard-action
// The findings below quote the exact policy fragments they detect, so the
// analyzer matches its own documentation. Nothing here is a policy document.
import { enclosingBlock, isCommentLine, makeFinding } from '../source';
import { buildTaintMap, isDirectUserInput } from '../taint';
import type { Finding, Rule, ScanTarget } from '../types';

/**
 * Access-control defects.
 *
 * Authorization bugs are the hardest class for a scanner, because the missing
 * thing is the bug: there is no dangerous function call to match on, only an
 * absent ownership check. So this rule works by *absence*, looking at three
 * shapes where the omission is visible in a single file:
 *
 *   - a record fetched by a client-supplied identifier with no tenant or owner
 *     predicate anywhere in the handler (IDOR);
 *   - a state-changing route registered with no authorization middleware or
 *     decorator between the path and the handler;
 *   - a trust decision made from data the client sent (`req.body.role`), or a
 *     resource opened up to everyone (`ACL: public-read`, `Principal: "*"`).
 *
 * Absence-based checks are inherently lower confidence than pattern matches, so
 * findings here are reported at medium confidence and phrased as questions a
 * reviewer should answer, not verdicts.
 */

/** A DB read keyed by an identifier. */
const LOOKUP_BY_ID =
  /\b(?:findByPk|findById|findOne|findFirst|findUnique|getById|get_or_404|get_object_or_404|objects\s*\.\s*get|\.first\s*\(|\.get\s*\(|SELECT\b[^;]*\bWHERE\b|query\s*\(|fetchOne|findOneBy)\b/i;

/** Evidence that the handler scopes the read to the caller. */
const OWNERSHIP_CHECK =
  /\b(?:req(?:uest)?\.user|ctx\.user|current_?user|currentUser|session\.user|auth\.user|@me|user_?id\s*[:=]|userId\s*[:=]|owner_?id|ownerId|tenant_?id|tenantId|organization_?id|org_?id|account_?id|accountId|created_?by|belongs_?to|authorize|can\s*\(|ability|policy|permit|checkAccess|assertOwner|ensureOwner|filter_by\s*\(\s*user|scope\s*\(|where\s*\(\s*\{\s*[^}]*user)/i;

/** State-changing route registrations across frameworks. */
const ROUTE_REGISTRATIONS: { pattern: RegExp; framework: string }[] = [
  {
    // app.post('/x', handler) - captures everything between path and close paren.
    pattern:
      /\b(?:app|router|server|api|fastify)\s*\.\s*(post|put|patch|delete|del)\s*\(\s*(['"`][^'"`]+['"`])\s*,([^)]*)\)/i,
    framework: 'Express-style',
  },
  {
    pattern: /@(?:app|blueprint|bp|router)\s*\.\s*(?:route|post|put|patch|delete)\s*\(\s*(['"][^'"]+['"])([^)]*)\)/i,
    framework: 'Flask/FastAPI',
  },
];

const AUTH_MIDDLEWARE =
  /\b(?:auth|authenticate|authenticated|authorize|authorise|requireAuth|require_?login|requireUser|requiresAuth|isAuthenticated|ensureAuth|ensureLoggedIn|verifyToken|checkAuth|jwtGuard|guard|protect|passport\s*\.\s*authenticate|login_required|jwt_required|permission_classes|Depends\s*\(|current_user|admin_?only|can\s*\(|acl|rbac|middleware\s*\.\s*auth)\b/i;

/** Frameworks that decorate the line(s) above the handler. */
const AUTH_DECORATOR =
  /@(?:login_required|jwt_required|permission_required|user_passes_test|requires_auth|authenticated|PreAuthorize|Secured|RolesAllowed|Authorize|admin_required|staff_member_required)\b/i;

/** Mass assignment: a whole request body written onto a model. */
const MASS_ASSIGNMENT =
  /(?:Object\.assign\s*\(\s*[^,]+,\s*(?:req|request)\s*\.\s*body|\.\s*(?:update|create|save|set|fill|assign)\s*\(\s*(?:req|request)\s*\.\s*body\s*\)|new\s+\w+\s*\(\s*(?:req|request)\s*\.\s*body\s*\)|\.\s*update\s*\(\s*\*\*request\.(?:json|data|form)\s*\)|\.\s*objects\s*\.\s*create\s*\(\s*\*\*request\.(?:POST|data)\s*\)|\{\s*\.\.\.(?:req|request)\s*\.\s*body\s*\})/;

/** Trust decisions taken from client-supplied fields. */
const CLIENT_CONTROLLED_ROLE =
  /\b(?:req|request|ctx)\s*\.\s*(?:body|query|params|headers|cookies)\s*(?:\.\s*|\[\s*['"])(?:role|roles|isAdmin|is_admin|admin|permissions?|scope|scopes|privilege|level|tier|plan|user_?type|access_?level|is_?staff|superuser)\b|\breq\.headers\s*\[\s*['"](?:x-user-(?:id|role)|x-admin|x-role|x-is-admin)['"]/i;

/** Wide-open resource policies. */
const PUBLIC_RESOURCE: { pattern: RegExp; id: string; title: string; detail: string; fix: string }[] = [
  {
    id: 'public-object-acl',
    pattern: /(?:ACL|acl)\s*[:=]\s*["'](?:public-read|public-read-write|authenticated-read)["']/,
    title: 'Object storage ACL grants public access',
    detail:
      'A `public-read` ACL makes the object readable by anyone who can guess or discover its URL, with no ' +
      'authentication and no audit trail. Bucket listings and search engine crawlers routinely surface these.',
    fix:
      'Keep the object private and hand out short-lived pre-signed URLs, or front the bucket with a CDN ' +
      'that enforces your own authorization.',
  },
  {
    id: 'iam-wildcard-principal',
    pattern: /["']Principal["']\s*:\s*(?:["']\*["']|\{\s*["']AWS["']\s*:\s*["']\*["'])/,
    title: 'IAM policy with a wildcard principal',
    detail:
      '`"Principal": "*"` grants the statement to every AWS account on earth. Combined with any ' +
      '`Allow` action this is a publicly callable resource.',
    fix:
      'Name the specific accounts, roles or service principals that need access, and add a `Condition` ' +
      '(such as `aws:SourceArn` or `aws:PrincipalOrgID`) to bound it further.',
  },
  {
    id: 'iam-wildcard-action',
    pattern: /["']Action["']\s*:\s*(?:["']\*["']|\[\s*["']\*["'])/,
    title: 'IAM policy allows every action',
    detail:
      '`"Action": "*"` is administrative access. Any compromise of a caller holding this policy is a ' +
      'compromise of the whole account.',
    fix: 'Enumerate the actions the workload actually calls and grant only those.',
  },
  {
    id: 'network-open-to-world',
    pattern: /(?:cidr_blocks|source_ranges|CidrIp|cidr_ipv4)\s*[:=]\s*\[?\s*["']0\.0\.0\.0\/0["']/,
    title: 'Security group open to the entire internet',
    detail:
      'A `0.0.0.0/0` ingress rule exposes the port to every host on the internet. For an admin, database ' +
      'or management port this is a direct path in.',
    fix:
      'Restrict the range to the load balancer security group, your VPN CIDR or a bastion. If public ' +
      'access is intended, confirm it is only ports 80 and 443.',
  },
  {
    id: 'permissive-cors-with-credentials',
    pattern: /origin\s*:\s*(?:["']\*["']|true)[^\n]{0,80}credentials\s*:\s*true|credentials\s*:\s*true[^\n]{0,80}origin\s*:\s*(?:["']\*["']|true)/,
    title: 'CORS allows any origin together with credentials',
    detail:
      'Reflecting the request origin while allowing credentials lets any website read authenticated ' +
      'responses from this API using the visitor\'s own session. It removes the same-origin protection ' +
      'that CSRF defences rely on.',
    fix:
      'Replace the wildcard with an explicit allow-list of trusted origins and reject anything else. ' +
      'A wildcard origin is only safe when `credentials` is false.',
  },
];

export const authorizationRule: Rule = {
  id: 'authorization',
  category: 'authorization',
  description:
    'Surfaces missing access control: object lookups without an ownership predicate, state-changing routes with no auth middleware, mass assignment, client-supplied roles and wide-open resource policies.',
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
      const block = enclosingBlock(target, lineNumber, 25);

      // --- IDOR --------------------------------------------------------------
      if (LOOKUP_BY_ID.test(raw) && isDirectUserInput(raw) && !OWNERSHIP_CHECK.test(block)) {
        findings.push(
          makeFinding(target, 'authorization', {
            ruleId: 'authorization/missing-ownership-check',
            severity: 'high',
            confidence: 'medium',
            title: 'Record fetched by a client-supplied ID with no ownership check',
            description:
              'The identifier comes straight from the request and the surrounding handler contains no ' +
              'predicate tying the record to the caller - no `req.user`, owner, tenant or policy check. ' +
              'If this endpoint is reachable by any authenticated user, changing the ID in the URL returns ' +
              "someone else's data. This is the most commonly exploited access-control bug in web APIs.",
            remediation:
              'Scope the query to the caller rather than filtering afterwards: ' +
              '`findOne({ id, userId: req.user.id })`. For shared resources, load the record and then run an ' +
              'explicit policy check before returning it. Prefer opaque or random IDs so records are not ' +
              'enumerable, but treat that as defence in depth, not the fix.',
            line: lineNumber,
            evidence: raw,
            cwe: ['CWE-639', 'CWE-863'],
          }),
        );
      }

      // --- Unprotected state-changing route ---------------------------------
      for (const { pattern, framework } of ROUTE_REGISTRATIONS) {
        const match = pattern.exec(raw);
        if (!match) continue;
        const handlerArgs = (match[3] ?? match[2] ?? '').trim();
        const decoratorContext = [
          target.lines[lineNumber - 2] ?? '',
          target.lines[lineNumber - 3] ?? '',
          target.lines[lineNumber] ?? '',
          target.lines[lineNumber + 1] ?? '',
        ].join('\n');

        const isStateChanging =
          /\b(post|put|patch|delete|del)\b/i.test(match[1] ?? '') ||
          /methods\s*=\s*\[[^\]]*(?:POST|PUT|PATCH|DELETE)/i.test(raw);
        if (!isStateChanging) continue;
        if (AUTH_MIDDLEWARE.test(handlerArgs) || AUTH_MIDDLEWARE.test(raw)) continue;
        if (AUTH_DECORATOR.test(decoratorContext) || AUTH_MIDDLEWARE.test(decoratorContext)) continue;
        // A router-level `router.use(auth)` protects everything below it.
        if (/\.\s*use\s*\(\s*[^)]*(?:auth|guard|protect|requireUser)/i.test(block)) continue;
        // Webhooks and health checks are intentionally unauthenticated.
        if (/webhook|health|ping|status|public|login|signin|signup|register|token|oauth|callback/i.test(raw)) continue;

        findings.push(
          makeFinding(target, 'authorization', {
            ruleId: 'authorization/unprotected-state-changing-route',
            severity: 'high',
            confidence: 'low',
            title: `${framework} ${(match[1] ?? 'route').toUpperCase()} route registered without an auth check`,
            description:
              'This route mutates state but no authentication or authorization middleware appears between ' +
              'the path and the handler, and none is applied at the router level nearby. If protection is ' +
              'applied somewhere further out, this is fine - the point is that a reader of this file cannot tell.',
            remediation:
              'Attach the auth middleware explicitly at the route (`router.post("/x", requireAuth, handler)`) ' +
              'or mount the router behind it. Making protection opt-out rather than opt-in - a global guard ' +
              'with an explicit public allow-list - removes this class of mistake entirely.',
            line: lineNumber,
            evidence: raw,
            cwe: ['CWE-306', 'CWE-862'],
          }),
        );
      }

      // --- Mass assignment ---------------------------------------------------
      if (MASS_ASSIGNMENT.test(raw)) {
        findings.push(
          makeFinding(target, 'authorization', {
            ruleId: 'authorization/mass-assignment',
            severity: 'high',
            confidence: 'medium',
            title: 'Request body written onto a model wholesale',
            description:
              'Every field the client sends is persisted, including ones the form never shows. Adding ' +
              '`"role":"admin"`, `"isVerified":true` or `"balance":999999` to the request body is enough to ' +
              'escalate privileges, because the model - not the endpoint - decides what is writable.',
            remediation:
              'Pick fields explicitly rather than spreading the body: destructure the handful you accept, ' +
              'or validate against a schema that strips unknown keys (zod `.strict()`, Joi ' +
              '`stripUnknown`, a serializer with an explicit field list). Keep privileged fields out of the ' +
              'writable set entirely.',
            line: lineNumber,
            evidence: raw,
            cwe: ['CWE-915'],
          }),
        );
      }

      // --- Client-supplied authorization data --------------------------------
      if (CLIENT_CONTROLLED_ROLE.test(raw)) {
        const isDecision = /\bif\b|\bwhen\b|===|==|\?|&&|\|\||switch|assert|require|allow|grant|can/i.test(raw);
        findings.push(
          makeFinding(target, 'authorization', {
            ruleId: 'authorization/client-supplied-role',
            severity: isDecision ? 'critical' : 'high',
            confidence: isDecision ? 'high' : 'medium',
            title: 'Privilege level read from the request',
            description:
              'Roles, permission flags and admin headers arriving in the request are attacker-controlled - ' +
              'a client can set them to anything. ' +
              (isDecision
                ? 'Here the value feeds a decision, so anyone can grant themselves whatever level they ask for.'
                : 'Even when only stored, the value later becomes the basis for decisions elsewhere.'),
            remediation:
              "Derive privileges server-side from the authenticated session - look the user's role up from " +
              'your own store keyed by the verified subject claim. If a trusted proxy really does inject an ' +
              'identity header, terminate that header at the edge so a client cannot forge it, and verify a ' +
              'signature on it.',
            line: lineNumber,
            evidence: raw,
            cwe: ['CWE-807', 'CWE-269'],
          }),
        );
      }

      // --- Wide-open resource policies --------------------------------------
      for (const entry of PUBLIC_RESOURCE) {
        if (!entry.pattern.test(raw)) continue;
        findings.push(
          makeFinding(target, 'authorization', {
            ruleId: `authorization/${entry.id}`,
            severity: entry.id === 'iam-wildcard-action' ? 'high' : 'high',
            confidence: 'high',
            title: entry.title,
            description: entry.detail,
            remediation: entry.fix,
            line: lineNumber,
            evidence: raw,
            cwe: ['CWE-732', 'CWE-284'],
          }),
        );
      }

      // --- Path traversal in file serving -----------------------------------
      if (
        /\b(?:sendFile|send_file|serve_file|readFile(?:Sync)?|createReadStream|open|File\s*\(|FileInputStream|os\.path\.join|path\.join|Paths\.get)\b/.test(
          raw,
        ) &&
        isDirectUserInput(raw) &&
        !/\b(?:basename|resolve\s*\([^)]*\)\s*\.\s*startsWith|normalize[^\n]*startsWith|realpath|safe_join|allowlist|whitelist|indexOf\s*\(\s*['"]\.\.|includes\s*\(\s*['"]\.\.)/.test(
          enclosingBlock(target, lineNumber, 8),
        )
      ) {
        findings.push(
          makeFinding(target, 'authorization', {
            ruleId: 'authorization/path-traversal',
            severity: 'high',
            confidence: 'medium',
            title: 'File path built from request input without containment',
            description:
              'A request-supplied path segment reaches a filesystem call with no check that the result stays ' +
              'inside the intended directory. `../../etc/passwd`, an absolute path, or an encoded variant ' +
              'reads arbitrary files the process can see - source, config, credentials.',
            remediation:
              'Resolve the joined path and assert it is still under the base directory ' +
              '(`const full = path.resolve(base, input); if (!full.startsWith(base + path.sep)) reject()`), ' +
              'or map the input through an allow-list of known filenames. `path.basename` alone strips ' +
              'directories but does not stop symlink escapes.',
            line: lineNumber,
            evidence: raw,
            cwe: ['CWE-22'],
          }),
        );
      }
    }

    void taint;
    return findings;
  },
};
