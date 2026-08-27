import type { Finding, ScanTarget } from '../analysis/types';

/**
 * What leaves the process.
 *
 * Triage sends source code to a third-party API, which is a decision the
 * operator makes knowingly - but the amount and content is ours to control, and
 * two rules apply without exception.
 *
 * Send the minimum. A bounded window around each finding is enough for a model
 * to judge it; whole files are not needed and would multiply both the cost and
 * the exposure. Overlapping windows in the same file are merged so a cluster of
 * findings does not send the same lines several times.
 *
 * Never send a credential. The scanner's whole job includes finding secrets, so
 * the excerpts it assembles are exactly the text most likely to contain one.
 * Every excerpt is scrubbed before it goes anywhere, including values the
 * secrets rule flagged and values it did not.
 */

/** Provider token formats plus the generic assignment shape. */
const CREDENTIAL_PATTERNS: RegExp[] = [
  /\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g,
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g,
  /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b/g,
  /\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}\b/g,
  /\bAIza[A-Za-z0-9_\-]{35}\b/g,
  /\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b/g,
  /\bnpm_[A-Za-z0-9]{30,}\b/g,
  /\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{10,}\b/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g,
];

/** `password = "..."` and friends: keep the shape, drop the value. */
const ASSIGNED_SECRET =
  /(\b(?:[A-Za-z0-9_]*)?(?:passwd|password|secret|token|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|client[_-]?secret|private[_-]?key|credential|bearer)(?:[A-Za-z0-9_]*)?\s*[:=]\s*)(["'`])([^"'`\n]{6,})\2/gi;

/** A password embedded in a connection string. */
const URL_PASSWORD =
  /\b([a-z+]{2,12}:\/\/[^:\s'"@/]+:)([^@\s'"]{3,})(@)/gi;

export function scrubCredentials(text: string): string {
  let out = text;
  for (const pattern of CREDENTIAL_PATTERNS) out = out.replace(pattern, '[redacted]');
  out = out.replace(ASSIGNED_SECRET, (_match, prefix: string, quote: string) => `${prefix}${quote}[redacted]${quote}`);
  out = out.replace(URL_PASSWORD, (_match, prefix: string, _value: string, suffix: string) => `${prefix}[redacted]${suffix}`);
  return out;
}

export interface Excerpt {
  filePath: string;
  language: string;
  /** Numbered source lines, credential values removed. */
  text: string;
  /** First and last line included, for the model to reason about positions. */
  startLine: number;
  endLine: number;
}

export interface ExcerptOptions {
  /** Lines of context on each side of a finding. */
  contextLines: number;
  /** Hard cap on lines per file, so one clustered file cannot dominate a request. */
  maxLinesPerFile: number;
}

/**
 * Builds one merged excerpt per file, covering every finding in that file.
 *
 * Merging matters for more than cost: a model shown three separate overlapping
 * windows from the same function will reason about them as three unrelated
 * fragments, and the surrounding check that makes one of them a non-issue may
 * fall outside all three.
 */
export function buildExcerpts(
  target: ScanTarget,
  findings: Finding[],
  options: ExcerptOptions,
): Excerpt | null {
  if (findings.length === 0) return null;

  const ranges: [number, number][] = findings
    .map((finding): [number, number] => [
      Math.max(1, finding.line - options.contextLines),
      Math.min(target.lines.length, (finding.endLine ?? finding.line) + options.contextLines),
    ])
    .sort((a, b) => a[0] - b[0]);

  // Merge overlapping and adjacent ranges.
  const merged: [number, number][] = [];
  for (const range of ranges) {
    const last = merged[merged.length - 1];
    if (last && range[0] <= last[1] + 1) {
      last[1] = Math.max(last[1], range[1]);
    } else {
      merged.push([range[0], range[1]]);
    }
  }

  const chunks: string[] = [];
  let emitted = 0;
  let startLine = Number.POSITIVE_INFINITY;
  let endLine = 0;
  let truncated = false;

  for (const [from, to] of merged) {
    if (emitted >= options.maxLinesPerFile) {
      truncated = true;
      break;
    }
    if (chunks.length > 0) chunks.push('    ...');
    for (let line = from; line <= to; line += 1) {
      if (emitted >= options.maxLinesPerFile) {
        truncated = true;
        break;
      }
      const source = target.lines[line - 1] ?? '';
      chunks.push(`${String(line).padStart(5, ' ')}  ${source}`);
      emitted += 1;
      startLine = Math.min(startLine, line);
      endLine = Math.max(endLine, line);
    }
  }

  if (chunks.length === 0) return null;
  if (truncated) chunks.push('    ... (excerpt truncated)');

  return {
    filePath: target.filePath,
    language: target.language,
    text: scrubCredentials(chunks.join('\n')),
    startLine: Number.isFinite(startLine) ? startLine : 1,
    endLine,
  };
}
