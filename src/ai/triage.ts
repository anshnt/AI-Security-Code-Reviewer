import { SEVERITY_RANK, SEVERITIES, type Finding, type ScanTarget, type Severity } from '../analysis/types';
import { logger } from '../util/logger';
import { Anthropic, connect, describeError, isRetryable, type ModelAccess, type ModelOptions } from './client';
import { buildExcerpts, type Excerpt } from './excerpt';

/**
 * Model-assisted triage.
 *
 * The deterministic analyzers answer "does this code match a dangerous shape?".
 * That is the right question for a scanner and the wrong question for a
 * reviewer, because the shape is often present and harmless - the ownership
 * check lives two functions up, the interpolated value is a compile-time
 * constant, the `exec` argument comes from a config file. Answering the second
 * question needs something that can read the surrounding code, which is what
 * this pass adds.
 *
 * Three constraints shape the design.
 *
 * It can never make the review worse. A refuted finding is not deleted; it is
 * moved out of the blocking set and into a clearly-labelled section, so a wrong
 * refutation costs attention rather than a missed vulnerability. Severity is
 * adjustable by at most one step, and only on high confidence. Any API failure
 * leaves the deterministic findings exactly as they were.
 *
 * It has to be cheap enough to run on every push. Findings are batched per file
 * and only the ones worth the money are sent - a hardcoded AWS key needs no
 * second opinion, and a finding the analyzer already rated low confidence is
 * where a second opinion is worth most.
 *
 * It must not leak. Everything sent is a bounded, credential-scrubbed excerpt;
 * see `excerpt.ts`.
 */

export const VERDICTS = ['confirmed', 'likely', 'unclear', 'refuted'] as const;
export type Verdict = (typeof VERDICTS)[number];

export interface TriageResult {
  verdict: Verdict;
  /** Why, in terms of the actual code. Replaces the generic description. */
  reasoning: string;
  /** Concrete fix for this code. Replaces the generic remediation when present. */
  fix?: string;
  /** Severity after adjustment, which may equal the original. */
  severity: Severity;
  /** Set when the pass moved severity, for display and for auditing. */
  severityChangedFrom?: Severity;
  confidence: 'high' | 'medium' | 'low';
  model: string;
}

/** A finding carrying the triage verdict, if it was triaged. */
export interface TriagedFinding extends Finding {
  triage?: TriageResult;
}

export interface TriageOptions extends ModelOptions {
  /** Only findings at or above this severity are sent. */
  minSeverity: Severity;
  /** Hard cap per review, so a pathological pull request cannot run up a bill. */
  maxFindings: number;
  /** Lines of context on each side of a finding. */
  contextLines: number;
  /** Cap on excerpt lines per file. */
  maxLinesPerFile: number;
  /** Reasoning effort passed to the model. */
  effort: 'low' | 'medium' | 'high' | 'xhigh' | 'max';
  /** Output token ceiling per request. */
  maxTokens: number;
}

const TOOL_NAME = 'report_triage';

const SYSTEM_PROMPT = `You are reviewing the output of a static security analyzer before it is shown to the author of a pull request.

For each finding you are given the analyzer's verdict, the rule that fired, and a numbered excerpt of the surrounding code. Decide whether the finding is real *in this code*, and say why in terms of what you can actually see.

Be skeptical in both directions.

- A pattern match is not a vulnerability. If the surrounding code already makes the finding harmless - the value is a compile-time constant, an ownership predicate is applied, the input is validated against an allow-list, the API is used in its safe form - say so and refute it.
- Absence of evidence is not evidence of absence. If the excerpt does not show enough to judge, answer "unclear" rather than guessing. Do not refute a finding merely because the excerpt is short.
- Do not soften a finding you believe is real. If anything, an analyzer that rated something "medium" may be understating a directly reachable injection.

Rules for your response:

- Reference specific line numbers from the excerpt. "Line 42 passes req.body.id straight into the query" is useful; "this may be unsafe" is not.
- Write the reasoning for the pull request author, who is a competent engineer in a hurry and has not read the rule's documentation. State the consequence, not the category.
- The fix must be specific to this code: name the variable, the function, the parameter. Do not restate generic advice.
- Adjust severity only when you have a concrete reason, and by one step at most. Leave it alone if in doubt.
- Judge only the findings you are given. Do not report new ones.
- Some values in the excerpt have been replaced with [redacted]. That is deliberate; treat such a value as present but unknown, and never treat the redaction itself as the finding.

Report every finding you were given, keyed by its fingerprint, using the ${TOOL_NAME} tool.`;

const TRIAGE_TOOL: Anthropic.Tool = {
  name: TOOL_NAME,
  description: 'Report a verdict for each finding that was provided.',
  input_schema: {
    type: 'object',
    additionalProperties: false,
    required: ['findings'],
    properties: {
      findings: {
        type: 'array',
        items: {
          type: 'object',
          additionalProperties: false,
          required: ['fingerprint', 'verdict', 'reasoning', 'confidence'],
          properties: {
            fingerprint: {
              type: 'string',
              description: 'The fingerprint of the finding being judged, copied exactly.',
            },
            verdict: {
              type: 'string',
              enum: [...VERDICTS],
              description:
                'confirmed: reachable and real. likely: probably real but not provable from the excerpt. ' +
                'unclear: not enough context to judge. refuted: the surrounding code makes this a non-issue.',
            },
            reasoning: {
              type: 'string',
              description:
                'Two to four sentences for the pull request author, citing line numbers from the excerpt.',
            },
            fix: {
              type: 'string',
              description: 'A concrete fix for this specific code. Omit if the finding is refuted.',
            },
            severity: {
              type: 'string',
              enum: [...SEVERITIES],
              description: 'Adjusted severity. Omit to keep the analyzer’s severity.',
            },
            confidence: {
              type: 'string',
              enum: ['high', 'medium', 'low'],
              description: 'How confident you are in this verdict.',
            },
          },
        },
      },
    },
  },
};

interface RawVerdict {
  fingerprint?: unknown;
  verdict?: unknown;
  reasoning?: unknown;
  fix?: unknown;
  severity?: unknown;
  confidence?: unknown;
}

export interface TriagePass {
  /** Findings with verdicts attached where triage ran. */
  findings: TriagedFinding[];
  /** How many findings were sent to the model. */
  triagedCount: number;
  /** How many came back refuted. */
  refutedCount: number;
  /** Populated when the pass could not run; the findings are returned untouched. */
  error?: string;
  model?: string;
  durationMs: number;
}

/**
 * Runs triage over a scan's findings. Never throws: a failure is reported in
 * the result and the original findings are returned unchanged.
 */
export async function triage(
  findings: Finding[],
  targets: Map<string, ScanTarget>,
  options: TriageOptions,
): Promise<TriagePass> {
  const started = Date.now();

  const eligible = selectForTriage(findings, options);
  if (eligible.length === 0) {
    return { findings, triagedCount: 0, refutedCount: 0, durationMs: Date.now() - started };
  }

  let access: ModelAccess;
  try {
    access = await connect(options);
  } catch (error) {
    const message = describeError(error);
    logger.warn('triage unavailable', { reason: message });
    return { findings, triagedCount: 0, refutedCount: 0, error: message, durationMs: Date.now() - started };
  }

  const byFile = new Map<string, Finding[]>();
  for (const finding of eligible) {
    const bucket = byFile.get(finding.filePath) ?? [];
    bucket.push(finding);
    byFile.set(finding.filePath, bucket);
  }

  const verdicts = new Map<string, TriageResult>();
  const failures: string[] = [];

  // Files are independent, so run them concurrently but bounded - a 200-file
  // pull request should not open 200 connections.
  const groups = [...byFile.entries()];
  const concurrency = Math.min(4, groups.length);
  let cursor = 0;

  async function worker(): Promise<void> {
    while (cursor < groups.length) {
      const index = cursor;
      cursor += 1;
      const entry = groups[index];
      if (!entry) return;
      const [filePath, group] = entry;
      const target = targets.get(filePath);
      if (!target) continue;
      const excerpt = buildExcerpts(target, group, {
        contextLines: options.contextLines,
        maxLinesPerFile: options.maxLinesPerFile,
      });
      if (!excerpt) continue;
      try {
        const results = await judgeFile(access, excerpt, group, options);
        for (const [fingerprint, result] of results) verdicts.set(fingerprint, result);
      } catch (error) {
        failures.push(`${filePath}: ${describeError(error)}`);
      }
    }
  }

  await Promise.all(Array.from({ length: concurrency }, () => worker()));

  if (failures.length > 0) {
    logger.warn('triage partially failed', { failures: failures.slice(0, 5), total: failures.length });
  }

  const applied: TriagedFinding[] = findings.map((finding) => {
    const result = verdicts.get(finding.fingerprint);
    if (!result) return finding;
    return {
      ...finding,
      severity: result.severity,
      triage: result,
    };
  });

  const refutedCount = applied.filter((finding) => finding.triage?.verdict === 'refuted').length;

  logger.info('triage complete', {
    model: access.model,
    sent: eligible.length,
    judged: verdicts.size,
    refuted: refutedCount,
    failedFiles: failures.length,
    durationMs: Date.now() - started,
  });

  return {
    findings: applied,
    triagedCount: verdicts.size,
    refutedCount,
    model: access.model,
    ...(failures.length > 0 && verdicts.size === 0
      ? { error: `every triage request failed (${failures.length} files)` }
      : {}),
    durationMs: Date.now() - started,
  };
}

/**
 * Chooses which findings are worth a second opinion.
 *
 * Ordered by where the value is highest rather than by severity alone: a
 * low-confidence finding is where the analyzer is least sure and a reviewer's
 * judgement helps most, so those go first within a severity band. Provider
 * secret matches are excluded outright - an AWS key is an AWS key, and asking a
 * model to confirm it would mean sending it somewhere.
 */
export function selectForTriage(findings: Finding[], options: TriageOptions): Finding[] {
  const minRank = SEVERITY_RANK[options.minSeverity];
  const CONFIDENCE_ORDER = { low: 0, medium: 1, high: 2 } as const;

  return findings
    .filter((finding) => SEVERITY_RANK[finding.severity] <= minRank)
    .filter((finding) => !isSelfEvident(finding))
    .sort((a, b) => {
      const bySeverity = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
      if (bySeverity !== 0) return bySeverity;
      return CONFIDENCE_ORDER[a.confidence] - CONFIDENCE_ORDER[b.confidence];
    })
    .slice(0, options.maxFindings);
}

/**
 * Findings a model cannot usefully second-guess. A provider-format credential
 * match is decided by the format itself, and the excerpt would have to contain
 * the credential for the model to judge it - which is precisely what must not
 * be sent.
 */
function isSelfEvident(finding: Finding): boolean {
  if (finding.category !== 'secrets') return false;
  return finding.ruleId !== 'secrets/hardcoded-credential';
}

async function judgeFile(
  access: ModelAccess,
  excerpt: Excerpt,
  findings: Finding[],
  options: TriageOptions,
): Promise<Map<string, TriageResult>> {
  const prompt = renderPrompt(excerpt, findings);

  const response = await withRetry(async () =>
    access.client.messages.create({
      model: access.model,
      max_tokens: options.maxTokens,
      system: SYSTEM_PROMPT,
      output_config: { effort: options.effort },
      tools: [TRIAGE_TOOL],
      messages: [{ role: 'user', content: prompt }],
    } as Anthropic.MessageCreateParamsNonStreaming),
  );

  return parseResponse(response, findings, access.model);
}

/** One retry on a transient failure; anything else surfaces immediately. */
async function withRetry<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (!isRetryable(error)) throw error;
    await new Promise((resolve) => setTimeout(resolve, 1500));
    return operation();
  }
}

export function renderPrompt(excerpt: Excerpt, findings: Finding[]): string {
  const lines: string[] = [
    `File: ${excerpt.filePath} (${excerpt.language})`,
    '',
    `${findings.length} finding${findings.length === 1 ? '' : 's'} to judge:`,
    '',
  ];

  for (const finding of findings) {
    lines.push(
      `- fingerprint: ${finding.fingerprint}`,
      `  line: ${finding.line}`,
      `  rule: ${finding.ruleId}`,
      `  analyzer severity: ${finding.severity} (${finding.confidence} confidence)`,
      `  analyzer claim: ${finding.title}`,
      `  analyzer reasoning: ${finding.description}`,
      '',
    );
  }

  lines.push(
    `Source excerpt, lines ${excerpt.startLine} to ${excerpt.endLine}:`,
    '',
    '```',
    excerpt.text,
    '```',
  );

  return lines.join('\n');
}

/**
 * Reads verdicts out of the response.
 *
 * Accepts either a tool call or a JSON object in the text, because the tool is
 * offered rather than forced - forcing it is incompatible with some model
 * configurations, and a permissive parser is cheaper than losing the whole
 * batch to a formatting difference. Every field is validated: an unrecognised
 * verdict, a fingerprint that was not in this batch, or a severity outside the
 * scale is dropped rather than trusted.
 */
export function parseResponse(
  response: Anthropic.Message,
  findings: Finding[],
  model: string,
): Map<string, TriageResult> {
  const bySeverity = new Map(findings.map((finding) => [finding.fingerprint, finding]));
  const out = new Map<string, TriageResult>();

  for (const raw of extractVerdicts(response)) {
    const fingerprint = typeof raw.fingerprint === 'string' ? raw.fingerprint : null;
    if (!fingerprint) continue;
    const original = bySeverity.get(fingerprint);
    // A fingerprint we did not ask about is either a hallucination or a
    // mismatched batch; either way it is not actionable.
    if (!original) continue;

    const verdict = (VERDICTS as readonly string[]).includes(String(raw.verdict))
      ? (raw.verdict as Verdict)
      : null;
    const reasoning = typeof raw.reasoning === 'string' ? raw.reasoning.trim() : '';
    if (!verdict || reasoning.length === 0) continue;

    const confidence = (['high', 'medium', 'low'] as string[]).includes(String(raw.confidence))
      ? (raw.confidence as TriageResult['confidence'])
      : 'medium';

    const severity = adjustSeverity(original.severity, raw.severity, confidence);
    const fix = typeof raw.fix === 'string' && raw.fix.trim().length > 0 ? raw.fix.trim() : undefined;

    out.set(fingerprint, {
      verdict,
      reasoning,
      ...(fix ? { fix } : {}),
      severity,
      ...(severity !== original.severity ? { severityChangedFrom: original.severity } : {}),
      confidence,
      model,
    });
  }

  return out;
}

function extractVerdicts(response: Anthropic.Message): RawVerdict[] {
  for (const block of response.content) {
    if (block.type === 'tool_use' && block.name === TOOL_NAME) {
      const input = block.input as { findings?: unknown };
      if (Array.isArray(input?.findings)) return input.findings as RawVerdict[];
    }
  }
  // Fall back to a JSON object in the text.
  for (const block of response.content) {
    if (block.type !== 'text') continue;
    const parsed = parseJsonObject(block.text);
    if (parsed && Array.isArray(parsed.findings)) return parsed.findings as RawVerdict[];
  }
  return [];
}

/** Finds the first balanced JSON object in a string. */
function parseJsonObject(text: string): { findings?: unknown } | null {
  const start = text.indexOf('{');
  if (start < 0) return null;
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let index = start; index < text.length; index += 1) {
    const char = text[index]!;
    if (inString) {
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') inString = false;
      continue;
    }
    if (char === '"') inString = true;
    else if (char === '{') depth += 1;
    else if (char === '}') {
      depth -= 1;
      if (depth === 0) {
        try {
          return JSON.parse(text.slice(start, index + 1)) as { findings?: unknown };
        } catch {
          return null;
        }
      }
    }
  }
  return null;
}

/**
 * Severity may move by one step, and only on a high-confidence verdict.
 *
 * Without the cap, a single confident-sounding response could turn a critical
 * injection into an informational note. One step is enough to correct a genuine
 * misrating and not enough to erase a finding.
 */
export function adjustSeverity(
  original: Severity,
  requested: unknown,
  confidence: TriageResult['confidence'],
): Severity {
  if (confidence !== 'high') return original;
  if (!(SEVERITIES as readonly string[]).includes(String(requested))) return original;
  const target = requested as Severity;
  const from = SEVERITY_RANK[original];
  const to = SEVERITY_RANK[target];
  if (Math.abs(to - from) > 1) {
    return SEVERITIES[to > from ? from + 1 : from - 1] ?? original;
  }
  return target;
}
