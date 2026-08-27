import { describe, expect, it } from 'vitest';
import { parsePatch, reconstructFromPatch, removedLines } from '../src/analysis/diff';

const PATCH = [
  '@@ -1,4 +1,6 @@',
  ' const express = require("express");',
  '-const old = 1;',
  '+const db = require("./db");',
  '+',
  ' function handler(req, res) {',
  '+  const id = req.params.id;',
  '   res.end();',
  ' }',
].join('\n');

describe('parsePatch', () => {
  it('maps added lines to their post-change line numbers', () => {
    const parsed = parsePatch(PATCH);
    expect([...parsed.changedLines].sort((a, b) => a - b)).toEqual([2, 3, 5]);
    expect(parsed.addedLines.get(2)).toBe('const db = require("./db");');
    expect(parsed.addedLines.get(5)).toBe('  const id = req.params.id;');
  });

  it('assigns diff positions that count the hunk header', () => {
    const parsed = parsePatch(PATCH);
    // Header is position 1, then one line per patch line.
    expect(parsed.positionByLine.get(1)).toBe(2);
    expect(parsed.positionByLine.get(2)).toBe(4);
  });

  it('tracks deletions against pre-change numbering', () => {
    const removed = removedLines(parsePatch(PATCH));
    expect(removed.get(2)).toBe('const old = 1;');
  });

  it('parses hunk headers without an explicit line count', () => {
    const parsed = parsePatch('@@ -1 +1 @@\n-a\n+b');
    expect(parsed.hunks[0]).toMatchObject({ oldStart: 1, oldCount: 1, newStart: 1, newCount: 1 });
    expect(parsed.addedLines.get(1)).toBe('b');
  });

  it('ignores the no-newline marker without consuming a position', () => {
    const parsed = parsePatch('@@ -1,1 +1,1 @@\n+a\n\\ No newline at end of file');
    expect(parsed.changedLines.size).toBe(1);
    expect(parsed.positionByLine.get(1)).toBe(2);
  });

  it('handles multiple hunks with independent numbering', () => {
    const parsed = parsePatch(
      ['@@ -1,2 +1,2 @@', ' a', '+b', '@@ -50,2 +50,3 @@', ' x', '+y', ' z'].join('\n'),
    );
    expect(parsed.changedLines.has(2)).toBe(true);
    expect(parsed.changedLines.has(51)).toBe(true);
    expect(parsed.hunks).toHaveLength(2);
  });

  it('returns an empty result for a missing patch', () => {
    const parsed = parsePatch(undefined);
    expect(parsed.hunks).toEqual([]);
    expect(parsed.changedLines.size).toBe(0);
  });

  it('reconstructs the visible portion of the post-change file', () => {
    const text = reconstructFromPatch(parsePatch(PATCH));
    const lines = text.split('\n');
    expect(lines[0]).toBe('const express = require("express");');
    expect(lines[1]).toBe('const db = require("./db");');
    expect(lines[4]).toBe('  const id = req.params.id;');
  });
});
