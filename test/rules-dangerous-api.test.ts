import { describe, expect, it } from 'vitest';
import { dangerousApiRule } from '../src/analysis/rules/dangerous-api';
import { expectRule, run } from './helpers';

describe('dangerous-api', () => {
  it('flags eval', () => {
    const findings = run(dangerousApiRule, 'src/calc.ts', 'const result = eval(expression);');
    const finding = expectRule(findings, 'dangerous-api/eval');
    expect(finding.cwe).toContain('CWE-95');
  });

  it('raises eval to critical when the argument is request-derived', () => {
    const findings = run(
      dangerousApiRule,
      'src/calc.ts',
      `
app.post('/calc', (req, res) => {
  res.json({ value: eval(req.body.expression) });
});
`,
    );
    expect(expectRule(findings, 'dangerous-api/eval').severity).toBe('critical');
  });

  it('flags shell execution built from request data', () => {
    const findings = run(
      dangerousApiRule,
      'src/git.ts',
      `
app.post('/clone', (req, res) => {
  exec('git clone ' + req.body.url, cb);
});
`,
    );
    const finding = expectRule(findings, 'dangerous-api/shell-exec');
    expect(finding.severity).toBe('critical');
  });

  it('does not flag exec with a fully static command', () => {
    const findings = run(dangerousApiRule, 'src/build.ts', "exec('npm run build', cb);");
    expect(findings.filter((f) => f.ruleId === 'dangerous-api/shell-exec')).toEqual([]);
  });

  it('flags shell: true', () => {
    const findings = run(dangerousApiRule, 'src/run.ts', "spawn('ls', args, { shell: true });");
    expectRule(findings, 'dangerous-api/shell-true');
  });

  it('flags subprocess with shell=True in Python', () => {
    const findings = run(
      dangerousApiRule,
      'app/tasks.py',
      `
def run(request):
    target = request.args.get('target')
    subprocess.run('ping ' + target, shell=True)
`,
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags pickle.loads', () => {
    const findings = run(dangerousApiRule, 'app/cache.py', 'obj = pickle.loads(blob)');
    expectRule(findings, 'dangerous-api/unsafe-deserialization');
  });

  it('flags yaml.load without a safe loader', () => {
    const findings = run(dangerousApiRule, 'app/conf.py', 'cfg = yaml.load(text)');
    expectRule(findings, 'dangerous-api/unsafe-deserialization');
  });

  it('does not flag yaml.safe_load', () => {
    const findings = run(dangerousApiRule, 'app/conf.py', 'cfg = yaml.safe_load(text)');
    expect(findings.filter((f) => f.ruleId === 'dangerous-api/unsafe-deserialization')).toEqual([]);
  });

  it('flags innerHTML assignment from request data', () => {
    const findings = run(
      dangerousApiRule,
      'src/render.ts',
      `
const name = new URLSearchParams(location.search).get('name');
container.innerHTML = '<h1>' + name + '</h1>';
`,
    );
    expectRule(findings, 'dangerous-api/html-injection-sink');
  });

  it('flags an outbound request to a user-supplied URL', () => {
    const findings = run(
      dangerousApiRule,
      'src/proxy.ts',
      `
app.get('/fetch', async (req, res) => {
  const response = await fetch(req.query.url);
  res.send(await response.text());
});
`,
    );
    const finding = expectRule(findings, 'dangerous-api/ssrf');
    expect(finding.cwe).toContain('CWE-918');
  });

  it('does not flag fetch to a static URL', () => {
    const findings = run(dangerousApiRule, 'src/api.ts', "const r = await fetch('https://api.internal/v1/health');");
    expect(findings.filter((f) => f.ruleId === 'dangerous-api/ssrf')).toEqual([]);
  });

  it('flags ECB mode', () => {
    const findings = run(dangerousApiRule, 'src/crypto.ts', "const c = crypto.createCipheriv('aes-256-ecb', key, null);");
    expectRule(findings, 'dangerous-api/weak-cipher');
  });

  it('flags an XML parser created without entity protection', () => {
    const findings = run(
      dangerousApiRule,
      'src/Parser.java',
      'DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();',
    );
    expectRule(findings, 'dangerous-api/xxe');
  });

  it('does not flag an XML parser with secure processing enabled', () => {
    const findings = run(
      dangerousApiRule,
      'src/Parser.java',
      `
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
`,
    );
    expect(findings.filter((f) => f.ruleId === 'dangerous-api/xxe')).toEqual([]);
  });

  it('flags a regex compiled from user input', () => {
    const findings = run(
      dangerousApiRule,
      'src/search.ts',
      `
app.get('/find', (req, res) => {
  const pattern = new RegExp(req.query.q);
  res.json(items.filter((i) => pattern.test(i.name)));
});
`,
    );
    expectRule(findings, 'dangerous-api/regex-from-user-input');
  });

  it('flags debug mode', () => {
    const findings = run(dangerousApiRule, 'app/settings.py', 'DEBUG = True');
    expectRule(findings, 'dangerous-api/debug-mode-enabled');
  });

  it('flags world-writable permissions', () => {
    const findings = run(dangerousApiRule, 'scripts/setup.sh', 'chmod 777 /opt/app/config');
    expectRule(findings, 'dangerous-api/world-writable-permissions');
  });

  it('skips import lines for unconditional sinks', () => {
    const findings = run(dangerousApiRule, 'app/main.py', 'import pickle');
    expect(findings).toEqual([]);
  });

  it('skips comment lines', () => {
    const findings = run(dangerousApiRule, 'src/notes.ts', '// never use eval(userInput) here');
    expect(findings).toEqual([]);
  });
});

describe('dangerous-api false positives', () => {
  it('does not treat a JavaScript template literal as shell command substitution', () => {
    const findings = run(
      dangerousApiRule,
      'src/users.ts',
      `
export async function getUser(req, res) {
  const id = req.params.id;
  const rows = await db.query(\`SELECT * FROM users WHERE id = \${id}\`);
  res.json(rows);
}
`,
    );
    expect(findings.map((f) => f.ruleId)).not.toContain('dangerous-api/shell-exec');
    expect(findings).toEqual([]);
  });

  it('still flags backtick command substitution in a shell script', () => {
    const findings = run(
      dangerousApiRule,
      'scripts/deploy.sh',
      ['TARGET="$1"', 'RESULT=`ping -c1 $TARGET`'].join('\n'),
    );
    expect(findings.map((f) => f.ruleId)).toContain('dangerous-api/backtick-command-substitution');
  });
});

describe('sink precision', () => {
  it('does not treat RegExp.prototype.exec as a shell call', () => {
    const findings = run(
      dangerousApiRule,
      'src/parse.ts',
      `
export function parse(req) {
  const raw = req.body.text;
  const match = PATTERN.exec(raw);
  return match ? match[1] : null;
}
`,
    );
    expect(findings.map((f) => f.ruleId)).not.toContain('dangerous-api/shell-exec');
  });

  it('still flags a bare exec call', () => {
    const findings = run(
      dangerousApiRule,
      'src/run.ts',
      ['const { exec } = require("child_process");', 'exec("ls " + req.query.dir);'].join('\n'),
    );
    expect(findings.map((f) => f.ruleId)).toContain('dangerous-api/shell-exec');
  });

  it('still flags child_process.exec', () => {
    const findings = run(
      dangerousApiRule,
      'src/run.ts',
      'child_process.exec("ls " + req.query.dir);',
    );
    expect(findings.map((f) => f.ruleId)).toContain('dangerous-api/shell-exec');
  });

  it('does not treat express.raw as an HTML sink', () => {
    const findings = run(
      dangerousApiRule,
      'src/server.ts',
      "app.post('/webhook', express.raw({ type: '*/*', limit: '10mb' }), handler);",
    );
    expect(findings.map((f) => f.ruleId)).not.toContain('dangerous-api/html-injection-sink');
    expect(findings.map((f) => f.ruleId)).not.toContain('dangerous-api/template-escaping-disabled');
  });

  it('flags mark_safe on request data in a template context', () => {
    const findings = run(
      dangerousApiRule,
      'app/views.py',
      ['def render(request):', '    bio = request.POST.get("bio")', '    return mark_safe(bio)'].join('\n'),
    );
    expect(findings.map((f) => f.ruleId)).toContain('dangerous-api/template-escaping-disabled');
  });

  it('treats a Python exec call as code evaluation, not a shell call', () => {
    const findings = run(dangerousApiRule, 'app/run.py', 'exec(user_supplied_code)');
    expect(findings.map((f) => f.ruleId)).toContain('dangerous-api/python-exec');
  });
});
