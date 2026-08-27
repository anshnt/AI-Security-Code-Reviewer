// security-review-ignore-file dangerous-api, sql-injection
// This file's content is a table of patterns that *describe* unsafe code. The
// analyzers would otherwise match their own definitions, which is noise rather
// than signal - the strings here are never executed.
import { blankStringLiterals, isCommentLine, makeFinding, stringLiterals } from '../source';
import { buildTaintMap, taintStrength, type TaintStrength } from '../taint';
import type { Finding, Rule, ScanTarget } from '../types';

/**
 * SQL injection detection.
 *
 * The signal we look for is structural: a string that reads like SQL, whose
 * text is assembled at runtime from something other than a literal. Every
 * language expresses that differently, so the rule reasons about three things
 * independently and only reports when at least two line up:
 *
 *   1. Is this SQL?            (statement keywords in the literal parts)
 *   2. Is it dynamically built? (concatenation, interpolation, %-formatting)
 *   3. Where does the value come from? (the shared taint map)
 *
 * Parameterised queries are the escape hatch that must never be flagged, so
 * placeholder syntax is checked first and short-circuits the whole rule.
 */

/** A statement keyword plus a clause keyword is a strong "this is SQL" signal. */
const SQL_STATEMENT =
  /\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|REPLACE\s+INTO|MERGE\s+INTO|UPSERT|CREATE\s+TABLE|DROP\s+TABLE|ALTER\s+TABLE|TRUNCATE|GRANT|WITH\s+\w+\s+AS)\b/i;
const SQL_CLAUSE =
  /\b(?:FROM|WHERE|VALUES|SET|JOIN|ORDER\s+BY|GROUP\s+BY|HAVING|LIMIT|OFFSET|RETURNING|INTO)\b/i;

/** Query-executing APIs. Seeing one of these lets us relax the keyword test. */
const QUERY_SINK =
  /\b(?:(?:execute|exec|executemany|executescript|executeQuery|executeUpdate|createQuery|createNativeQuery|prepareStatement|rawQuery|query|queryRaw|queryAll|queryOne|queryRow|Query|QueryRow|QueryContext|ExecContext|Exec|raw|unsafe|sequelize\.query|knex\.raw|db\.raw|\$queryRawUnsafe|\$executeRawUnsafe|find_by_sql|where|from_query|mysql_query|mysqli_query|pg_query)\s*\()/;

/**
 * Placeholder styles across drivers: `?`, `$1`, `:name`, `%s`, `@name`, `{0}`.
 * When a literal uses these, the driver is doing the escaping.
 */
const PLACEHOLDER = /(?:\?|\$\d+|:[A-Za-z_][A-Za-z0-9_]*|%\((?:\w+)\)s|@[A-Za-z_][A-Za-z0-9_]*)/;

/** JS/TS template interpolation, Python f-strings, PHP/Ruby/shell interpolation. */
const INTERPOLATION = /\$\{[^}]+\}|#\{[^}]+\}|\{[A-Za-z_][A-Za-z0-9_.\[\]'"]*\}/;

/** `%s`-style formatting and `.format(...)` are Python's classic injection route. */
const PY_FORMAT = /%\s*[\(%sdrf]|\.format\s*\(/;

const CWE = ['CWE-89'];

/** Only these expressions are safe to interpolate into SQL text. */
const SAFE_INTERPOLATION = /^\s*(?:[A-Z][A-Z0-9_]*|(?:this\.)?[A-Za-z_$][\w$]*\.(?:table|tableName|TABLE|schema|name))\s*$/;

/**
 * A literal that *begins* with SQL syntax. Co-occurrence of keywords is far too
 * weak on its own: "Please select from the list of options" contains both
 * SELECT and FROM, and real SQL strings always start with a statement verb or -
 * for a concatenated fragment - a clause keyword.
 */
const LEADING_STATEMENT =
  /^\s*\(?\s*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|REPLACE\s+INTO|MERGE\s+INTO|UPSERT|CREATE\s+TABLE|DROP\s+TABLE|ALTER\s+TABLE|TRUNCATE|GRANT|WITH\s+\w+\s+AS)\b/i;
const LEADING_CLAUSE =
  /^\s*(?:WHERE|VALUES|SET|ORDER\s+BY|GROUP\s+BY|HAVING|LIMIT|OFFSET|RETURNING|INTO|FROM|(?:INNER\s+|LEFT\s+|RIGHT\s+|OUTER\s+)?JOIN)\b/i;
/** Comparison or membership syntax - present in essentially every real fragment. */
const SQL_OPERATOR = /[=<>]|\bLIKE\b|\bIN\s*\(|\bVALUES\s*\(|\bIS\s+(?:NOT\s+)?NULL\b/i;

function looksLikeSql(literals: string[]): boolean {
  const joined = literals.join(' ');
  if (literals.some((literal) => LEADING_STATEMENT.test(literal))) {
    return SQL_CLAUSE.test(joined) || /\b(?:DROP\s+TABLE|TRUNCATE|CREATE\s+TABLE|GRANT)\b/i.test(joined);
  }
  // A continuation fragment such as `" WHERE id = "` is SQL only if the wider
  // statement also reads like a query rather than like a sentence.
  if (literals.some((literal) => LEADING_CLAUSE.test(literal))) {
    return SQL_OPERATOR.test(joined);
  }
  return false;
}

function severityFor(strength: TaintStrength): Finding['severity'] {
  if (strength === 'direct' || strength === 'variable') return 'critical';
  if (strength === 'naming') return 'high';
  return 'medium';
}

function confidenceFor(strength: TaintStrength): Finding['confidence'] {
  if (strength === 'direct') return 'high';
  if (strength === 'variable') return 'high';
  if (strength === 'naming') return 'medium';
  return 'low';
}

/**
 * Collects a statement that spans several lines so multi-line query builders
 * are judged as a whole. Stops at a line without a trailing continuation.
 */
function statementAt(target: ScanTarget, line: number, maxLines = 8): { text: string; endLine: number } {
  let text = target.lines[line - 1] ?? '';
  let end = line;
  const opens = (value: string): number =>
    (value.match(/[([`]/g) ?? []).length - (value.match(/[)\]`]/g) ?? []).length;
  let depth = opens(text);
  while (end - line < maxLines && (depth > 0 || /[+,]\s*$/.test(text.trimEnd()))) {
    const next = target.lines[end];
    if (next === undefined) break;
    text += `\n${next}`;
    depth += opens(next);
    end += 1;
  }
  return { text, endLine: end };
}

export const sqlInjectionRule: Rule = {
  id: 'sql-injection',
  category: 'sql-injection',
  description:
    'Flags SQL statements assembled by concatenation or interpolation instead of driver-level parameter binding.',
  languages: ['*'],
  skipLanguages: ['documentation'],

  check(target: ScanTarget): Finding[] {
    const findings: Finding[] = [];
    const taint = buildTaintMap(target);
    const reported = new Set<number>();

    const candidateLines =
      target.changedLines ?? new Set(target.lines.map((_, index) => index + 1));

    for (const lineNumber of [...candidateLines].sort((a, b) => a - b)) {
      const raw = target.lines[lineNumber - 1];
      if (raw === undefined || isCommentLine(raw)) continue;
      if (reported.has(lineNumber)) continue;

      const { text, endLine } = statementAt(target, lineNumber);
      const literals = stringLiterals(text);
      const hasSink = QUERY_SINK.test(text);
      const isSql = looksLikeSql(literals);
      if (!isSql && !(hasSink && literals.some((l) => SQL_STATEMENT.test(l)))) continue;

      const finding = inspectStatement(target, lineNumber, endLine, text, literals, taint);
      if (finding) {
        findings.push(finding);
        for (let i = lineNumber; i <= endLine; i += 1) reported.add(i);
      }
    }

    return findings;
  },
};

function inspectStatement(
  target: ScanTarget,
  line: number,
  endLine: number,
  text: string,
  literals: string[],
  taint: ReturnType<typeof buildTaintMap>,
): Finding | null {
  const structural = blankStringLiterals(text);

  // --- 1. Template-literal / f-string / interpolation ------------------------
  for (const literal of literals) {
    if (!SQL_STATEMENT.test(literal) && !SQL_CLAUSE.test(literal)) continue;
    const matches = literal.match(new RegExp(INTERPOLATION, 'g'));
    if (!matches) continue;
    for (const match of matches) {
      const inner = match.replace(/^[$#]?\{/, '').replace(/\}$/, '');
      if (SAFE_INTERPOLATION.test(inner)) continue;
      const strength = taintStrength(inner, taint);
      return makeFinding(target, 'sql-injection', {
        ruleId: 'sql-injection/interpolated-query',
        severity: severityFor(strength),
        confidence: confidenceFor(strength),
        title: 'SQL query built by string interpolation',
        description:
          `The value \`${inner.trim()}\` is interpolated straight into SQL text, so an attacker who ` +
          'controls it controls the shape of the statement, not just the data in it. ' +
          describeTaint(strength, inner.trim()),
        remediation:
          'Bind the value as a parameter instead of splicing it into the string - ' +
          '`WHERE id = ?` / `WHERE id = $1` with the value passed in the parameter array. ' +
          'If the dynamic part is an identifier (table or column name) it cannot be bound: ' +
          'validate it against a hard-coded allow-list.',
        line,
        endLine: endLine > line ? endLine : undefined,
        evidence: text,
        cwe: CWE,
      });
    }
  }

  // --- 2. Concatenation of a SQL literal with an expression -----------------
  // Look at the structural view so `"a + b"` inside a literal is not a match.
  if (/["'`]\s*\+|\+\s*["'`]|["'`]\s*\.\s*\$|\|\|/.test(structural) && looksLikeSql(literals)) {
    const operand = concatenatedOperand(text);
    if (operand && !SAFE_INTERPOLATION.test(operand)) {
      const strength = taintStrength(operand, taint);
      {
        return makeFinding(target, 'sql-injection', {
          ruleId: 'sql-injection/string-concatenation',
          severity: severityFor(strength),
          confidence: confidenceFor(strength),
          title: 'SQL query built by string concatenation',
          description:
            `\`${operand.trim()}\` is concatenated into a SQL statement. String concatenation cannot ` +
            'distinguish data from syntax, so a value containing a quote or a comment marker rewrites ' +
            'the query. ' + describeTaint(strength, operand.trim()),
          remediation:
            'Use a prepared statement and pass the value as a bound parameter. ' +
            'Most drivers accept `connection.query(sql, [value])`; ORMs expose `where({ id })`.',
          line,
          endLine: endLine > line ? endLine : undefined,
          evidence: text,
          cwe: CWE,
        });
      }
    }
  }

  // --- 3. Python %-formatting and .format() --------------------------------
  if (
    (target.language === 'python' || target.language === 'other') &&
    PY_FORMAT.test(structural) &&
    looksLikeSql(literals) &&
    !literals.some((literal) => /%\((?:\w+)\)s/.test(literal) && !/\.format/.test(structural))
  ) {
    const strength = taintStrength(text, taint);
    return makeFinding(target, 'sql-injection', {
      ruleId: 'sql-injection/python-string-formatting',
      severity: severityFor(strength),
      confidence: strength === 'none' ? 'low' : confidenceFor(strength),
      title: 'SQL query built with Python string formatting',
      description:
        '`%` formatting and `str.format()` do no SQL escaping - they are ordinary text substitution. ' +
        'The DB-API driver never sees the value as data. ' + describeTaint(strength, 'the formatted value'),
      remediation:
        'Pass parameters to the driver instead: `cursor.execute("SELECT * FROM t WHERE id = %s", (user_id,))`. ' +
        'Note the comma - the second argument must be a sequence, not a formatted string.',
      line,
      endLine: endLine > line ? endLine : undefined,
      evidence: text,
      cwe: CWE,
    });
  }

  // --- 4. Explicitly-unsafe escape hatches ---------------------------------
  const unsafeApi =
    /\$queryRawUnsafe|\$executeRawUnsafe|\bknex\s*\.\s*raw\s*\(|\bdb\s*\.\s*raw\s*\(|sequelize\s*\.\s*query\s*\(|\.unsafe\s*\(|find_by_sql\s*\(/.exec(
      text,
    );
  if (unsafeApi && !PLACEHOLDER.test(literals.join(' '))) {
    const strength = taintStrength(text, taint);
    if (strength !== 'none') {
      return makeFinding(target, 'sql-injection', {
        ruleId: 'sql-injection/raw-query-api',
        severity: strength === 'direct' ? 'critical' : 'high',
        confidence: strength === 'naming' ? 'low' : 'medium',
        title: `Raw SQL API \`${unsafeApi[0].trim()}\` called with request-derived input`,
        description:
          'This API deliberately bypasses the ORM query builder and its escaping. Reaching it with ' +
          'request data hands an attacker a direct channel to the database.',
        remediation:
          'Prefer the query builder (`where`, `findMany`) which parameterises automatically. If raw SQL is ' +
          'genuinely required, use the tagged/parameterised variant (`$queryRaw`, `knex.raw("... ?", [value])`).',
        line,
        endLine: endLine > line ? endLine : undefined,
        evidence: text,
        cwe: CWE,
      });
    }
  }

  return null;
}

/**
 * Pulls the non-literal side out of a `"sql" + expr` concatenation.
 *
 * A statement is frequently built from several literals joined together
 * (`"SELECT ... " + "WHERE x = " + value`), so the first operand after a `+` is
 * often just another literal. Those are harmless - we want the first operand
 * that is an *expression*.
 */
function concatenatedOperand(text: string): string | null {
  const patterns = [
    /["'`][ \t\r\n]*(?:\+|\.|\|\|)[ \t\r\n]*([^+;)\n]+)/g,
    /([A-Za-z_$][\w$.\[\]()'"]*)[ \t]*(?:\+|\.|\|\|)[ \t]*["'`]/g,
  ];
  for (const pattern of patterns) {
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(text))) {
      const operand = match[1]?.trim();
      if (!operand) continue;
      // Skip literal operands - concatenating two constants is not injection.
      if (/^["'`]/.test(operand)) continue;
      return operand;
    }
  }
  return null;
}

function describeTaint(strength: TaintStrength, subject: string): string {
  switch (strength) {
    case 'direct':
      return `\`${subject}\` is read directly from the incoming request.`;
    case 'variable':
      return `\`${subject}\` was traced back to request data earlier in this file.`;
    case 'naming':
      return `The name \`${subject}\` suggests externally supplied data - confirm where it originates.`;
    default:
      return 'Confirm whether this value can ever be influenced by a caller.';
  }
}
