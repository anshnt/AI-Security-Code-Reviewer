/**
 * Unified-diff parsing.
 *
 * The reviewer needs two things from a patch: which lines the author touched
 * (so we only report on their work, not on pre-existing debt) and the mapping
 * from a file line to a diff position (so review comments can be anchored
 * inline). GitHub gives us per-file patches, so we parse those directly rather
 * than pulling a dependency.
 */

export interface DiffLine {
  kind: 'add' | 'del' | 'context';
  content: string;
  /** Line number in the post-change file. Absent for deletions. */
  newLine?: number;
  /** Line number in the pre-change file. Absent for additions. */
  oldLine?: number;
  /**
   * Offset of this line within the file's patch, counting from 1 at the first
   * hunk header. This is the `position` value the GitHub review API expects.
   */
  position: number;
}

export interface DiffHunk {
  oldStart: number;
  oldCount: number;
  newStart: number;
  newCount: number;
  header: string;
  lines: DiffLine[];
}

export interface ParsedPatch {
  hunks: DiffHunk[];
  /** Post-change line numbers that were added or replaced. */
  changedLines: Set<number>;
  /** Post-change line number to diff position, for inline comment anchoring. */
  positionByLine: Map<number, number>;
  /** Post-change line number to its added content. */
  addedLines: Map<number, string>;
}

const HUNK_HEADER = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$/;

export function parsePatch(patch: string | undefined | null): ParsedPatch {
  const result: ParsedPatch = {
    hunks: [],
    changedLines: new Set<number>(),
    positionByLine: new Map<number, number>(),
    addedLines: new Map<number, string>(),
  };
  if (!patch) return result;

  let hunk: DiffHunk | null = null;
  let oldLine = 0;
  let newLine = 0;
  let position = 0;

  for (const raw of patch.split('\n')) {
    const header = HUNK_HEADER.exec(raw);
    if (header) {
      position += 1; // the hunk header itself occupies a position
      hunk = {
        oldStart: Number(header[1]),
        oldCount: header[2] === undefined ? 1 : Number(header[2]),
        newStart: Number(header[3]),
        newCount: header[4] === undefined ? 1 : Number(header[4]),
        header: (header[5] ?? '').trim(),
        lines: [],
      };
      oldLine = hunk.oldStart;
      newLine = hunk.newStart;
      result.hunks.push(hunk);
      continue;
    }
    if (!hunk) continue;
    // "\ No newline at end of file" carries no line and no position.
    if (raw.startsWith('\\')) continue;

    const marker = raw[0];
    const content = raw.slice(1);
    position += 1;

    if (marker === '+') {
      const line: DiffLine = { kind: 'add', content, newLine, position };
      hunk.lines.push(line);
      result.changedLines.add(newLine);
      result.positionByLine.set(newLine, position);
      result.addedLines.set(newLine, content);
      newLine += 1;
    } else if (marker === '-') {
      hunk.lines.push({ kind: 'del', content, oldLine, position });
      oldLine += 1;
    } else {
      hunk.lines.push({ kind: 'context', content, newLine, oldLine, position });
      result.positionByLine.set(newLine, position);
      newLine += 1;
      oldLine += 1;
    }
  }

  return result;
}

/**
 * Reconstructs as much of the post-change file as the patch reveals. Used when
 * the full file cannot be fetched (very large files, or offline runs): context
 * plus added lines still gives rules useful surroundings.
 */
export function reconstructFromPatch(parsed: ParsedPatch): string {
  const byLine = new Map<number, string>();
  let maxLine = 0;
  for (const hunk of parsed.hunks) {
    for (const line of hunk.lines) {
      if (line.newLine === undefined) continue;
      byLine.set(line.newLine, line.content);
      if (line.newLine > maxLine) maxLine = line.newLine;
    }
  }
  const out: string[] = [];
  for (let i = 1; i <= maxLine; i += 1) out.push(byLine.get(i) ?? '');
  return out.join('\n');
}

/** Lines removed by the patch, keyed by pre-change line number. */
export function removedLines(parsed: ParsedPatch): Map<number, string> {
  const out = new Map<number, string>();
  for (const hunk of parsed.hunks) {
    for (const line of hunk.lines) {
      if (line.kind === 'del' && line.oldLine !== undefined) out.set(line.oldLine, line.content);
    }
  }
  return out;
}
