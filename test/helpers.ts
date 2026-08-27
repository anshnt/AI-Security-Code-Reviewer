import { buildTarget } from '../src/analysis/engine';
import type { Finding, Rule, ScanTarget } from '../src/analysis/types';

/** Builds a whole-file scan target, the shape a rule sees for a new file. */
export function target(filePath: string, source: string, status: ScanTarget['status'] = 'added'): ScanTarget {
  return buildTarget({
    filePath,
    content: source.replace(/^\n/, ''),
    status,
    changedLines: null,
  });
}

export function run(rule: Rule, filePath: string, source: string): Finding[] {
  return rule.check(target(filePath, source));
}

export function ruleIds(findings: Finding[]): string[] {
  return findings.map((finding) => finding.ruleId);
}

/** Asserts a rule fired, and returns the matching finding for further checks. */
export function expectRule(findings: Finding[], ruleId: string): Finding {
  const found = findings.find((finding) => finding.ruleId === ruleId);
  if (!found) {
    throw new Error(
      `expected rule ${ruleId} to fire; got: ${findings.map((f) => f.ruleId).join(', ') || '(none)'}`,
    );
  }
  return found;
}
