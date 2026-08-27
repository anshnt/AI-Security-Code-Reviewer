import { describe, expect, it } from 'vitest';
import { sqlInjectionRule } from '../src/analysis/rules/sql-injection';
import { expectRule, ruleIds, run } from './helpers';

describe('sql-injection', () => {
  it('flags a template literal splicing request data into a query', () => {
    const findings = run(
      sqlInjectionRule,
      'src/users.ts',
      `
export async function getUser(req, res) {
  const id = req.params.id;
  const rows = await db.query(\`SELECT * FROM users WHERE id = \${id}\`);
  res.json(rows);
}
`,
    );
    const finding = expectRule(findings, 'sql-injection/interpolated-query');
    expect(finding.severity).toBe('critical');
    expect(finding.confidence).toBe('high');
    expect(finding.cwe).toContain('CWE-89');
    expect(finding.line).toBe(3);
  });

  it('flags concatenation of a request value into a query', () => {
    const findings = run(
      sqlInjectionRule,
      'src/search.js',
      `
app.get('/search', (req, res) => {
  const sql = "SELECT id, name FROM products WHERE name LIKE '%" + req.query.term + "%'";
  connection.query(sql, cb);
});
`,
    );
    const finding = expectRule(findings, 'sql-injection/string-concatenation');
    expect(finding.severity).toBe('critical');
  });

  it('flags Python percent-formatting in a cursor call', () => {
    const findings = run(
      sqlInjectionRule,
      'app/views.py',
      `
def orders(request):
    status = request.GET.get('status')
    cursor.execute("SELECT * FROM orders WHERE status = '%s'" % status)
    return cursor.fetchall()
`,
    );
    expectRule(findings, 'sql-injection/python-string-formatting');
  });

  it('flags an f-string query', () => {
    const findings = run(
      sqlInjectionRule,
      'app/db.py',
      `
def fetch(request):
    table = request.args.get('table')
    cursor.execute(f"SELECT * FROM logs WHERE source = {table}")
`,
    );
    expect(ruleIds(findings).length).toBeGreaterThan(0);
  });

  it('does not flag a parameterised query', () => {
    const findings = run(
      sqlInjectionRule,
      'src/users.ts',
      `
export async function getUser(req, res) {
  const id = req.params.id;
  const rows = await db.query('SELECT * FROM users WHERE id = ?', [id]);
  res.json(rows);
}
`,
    );
    expect(findings).toEqual([]);
  });

  it('does not flag a numbered-placeholder query', () => {
    const findings = run(
      sqlInjectionRule,
      'src/repo.ts',
      `
const email = req.body.email;
const { rows } = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
`,
    );
    expect(findings).toEqual([]);
  });

  it('does not flag a fully static query', () => {
    const findings = run(
      sqlInjectionRule,
      'src/stats.ts',
      `
const rows = await db.query('SELECT COUNT(*) FROM users WHERE active = true');
`,
    );
    expect(findings).toEqual([]);
  });

  it('does not flag prose that happens to contain a SQL keyword', () => {
    const findings = run(
      sqlInjectionRule,
      'src/messages.ts',
      `
const message = 'Please select from the list of options ' + userName;
`,
    );
    expect(findings).toEqual([]);
  });

  it('allows an allow-listed constant to be interpolated', () => {
    const findings = run(
      sqlInjectionRule,
      'src/repo.ts',
      `
const TABLE_NAME = 'users';
const rows = await db.query(\`SELECT * FROM \${TABLE_NAME} WHERE id = ?\`, [id]);
`,
    );
    expect(findings).toEqual([]);
  });

  it('reports a raw ORM escape hatch reached by request data', () => {
    const findings = run(
      sqlInjectionRule,
      'src/reports.ts',
      `
const order = req.query.order;
const rows = await prisma.$queryRawUnsafe('SELECT * FROM reports ORDER BY ' + order);
`,
    );
    expect(ruleIds(findings).length).toBeGreaterThan(0);
    expect(findings[0]!.severity).toBe('critical');
  });

  it('reports once per statement rather than once per line', () => {
    const findings = run(
      sqlInjectionRule,
      'src/multi.ts',
      `
const name = req.body.name;
const sql = 'SELECT * FROM users ' +
  'WHERE name = ' + name +
  ' LIMIT 1';
`,
    );
    expect(findings).toHaveLength(1);
  });
});
