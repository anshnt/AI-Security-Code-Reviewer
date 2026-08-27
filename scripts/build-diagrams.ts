// security-review-ignore-file dangerous-api
// The severity table below names the APIs it illustrates, so the analyzers
// match their own documentation. These are labels in a diagram, not calls.
/**
 * Generates the README diagrams as SVG, one file per theme.
 *
 *   npx tsx scripts/build-diagrams.ts
 *
 * GitHub does not honour `prefers-color-scheme` inside an SVG, so a
 * theme-aware diagram has to be two files selected by a `<picture>` element in
 * the Markdown. Two hand-maintained files drift, so both are emitted from the
 * one description below and the only difference between them is the palette.
 *
 * The palette is the same one the dashboard uses, and it was checked with a
 * colour validator rather than by eye - see `src/dashboard/theme.ts`.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { DARK, LIGHT, type Palette } from '../src/dashboard/theme';

const OUT_DIR = 'docs/images';

interface Box {
  x: number;
  y: number;
  width: number;
  height: number;
  title: string;
  lines: string[];
  /** Accent stripe down the left edge. */
  accent?: 'primary' | 'secondary';
}

function escapeXml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function box(entry: Box, palette: Palette): string {
  const accent =
    entry.accent === 'primary'
      ? palette.series1
      : entry.accent === 'secondary'
        ? palette.series2
        : null;
  const parts: string[] = [
    `<rect x="${entry.x}" y="${entry.y}" width="${entry.width}" height="${entry.height}" rx="10" ` +
      `fill="${palette.surfaceRaised}" stroke="${palette.border}" stroke-width="1"/>`,
  ];
  if (accent) {
    // A 3px stripe inset from the rounded corners, so it never pokes outside
    // the card outline.
    parts.push(
      `<rect x="${entry.x}" y="${entry.y + 11}" width="3" height="${entry.height - 22}" rx="1.5" fill="${accent}"/>`,
    );
  }
  parts.push(
    `<text x="${entry.x + 18}" y="${entry.y + 26}" font-family="${FONT}" font-size="14" ` +
      `font-weight="600" fill="${palette.textPrimary}">${escapeXml(entry.title)}</text>`,
  );
  entry.lines.forEach((line, index) => {
    parts.push(
      `<text x="${entry.x + 18}" y="${entry.y + 48 + index * 17}" font-family="${FONT}" ` +
        `font-size="12" fill="${palette.textSecondary}">${escapeXml(line)}</text>`,
    );
  });
  return parts.join('\n  ');
}

function arrow(x1: number, y1: number, x2: number, y2: number, palette: Palette): string {
  return (
    `<path d="M ${x1} ${y1} L ${x2} ${y2}" stroke="${palette.textMuted}" stroke-width="1.5" ` +
    `fill="none" marker-end="url(#arrowhead)"/>`
  );
}

function label(x: number, y: number, text: string, palette: Palette, anchor = 'middle'): string {
  return (
    `<text x="${x}" y="${y}" text-anchor="${anchor}" font-family="${FONT}" font-size="11" ` +
    `fill="${palette.textMuted}">${escapeXml(text)}</text>`
  );
}

const FONT = "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif";

function document(width: number, height: number, palette: Palette, body: string): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" role="img">
  <rect width="${width}" height="${height}" rx="12" fill="${palette.surface}"/>
  <defs>
    <marker id="arrowhead" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 1 L 9 5 L 0 9 z" fill="${palette.textMuted}"/>
    </marker>
  </defs>
  ${body}
</svg>
`;
}

/** The review pipeline, left to right, with the three outputs it produces. */
function pipeline(palette: Palette): string {
  const boxes: Box[] = [
    {
      x: 24, y: 96, width: 190, height: 104,
      title: 'Pull request event',
      lines: ['HMAC verified against', 'the raw request body', 'before any parsing'],
      accent: 'primary',
    },
    {
      x: 254, y: 96, width: 190, height: 104,
      title: 'Diff and file fetch',
      lines: ['Changed lines from the', 'patch, full file at head', 'for surrounding context'],
      accent: 'primary',
    },
    {
      x: 484, y: 52, width: 214, height: 192,
      title: 'Six analyzers',
      lines: [
        'SQL injection',
        'Authentication',
        'Secrets',
        'Dependencies',
        'Authorization',
        'Dangerous APIs',
        '',
        'plus a shared taint pass',
      ],
      accent: 'primary',
    },
    {
      x: 738, y: 96, width: 190, height: 104,
      title: 'Rank and filter',
      lines: ['Severity by reachability,', 'reported only on lines', 'the author changed'],
      accent: 'primary',
    },
    {
      x: 968, y: 24, width: 208, height: 74,
      title: 'Review comment',
      lines: ['One comment, kept', 'up to date in place'],
      accent: 'secondary',
    },
    {
      x: 968, y: 114, width: 208, height: 74,
      title: 'Commit status',
      lines: ['Fails at your chosen', 'severity, gates merge'],
      accent: 'secondary',
    },
    {
      x: 968, y: 204, width: 208, height: 74,
      title: 'Trend dashboard',
      lines: ['Lifecycle recorded for', 'over-time reporting'],
      accent: 'secondary',
    },
  ];

  const body = [
    ...boxes.map((entry) => box(entry, palette)),
    arrow(214, 148, 250, 148, palette),
    arrow(444, 148, 480, 148, palette),
    arrow(698, 148, 734, 148, palette),
    // Fan out to the three outputs.
    `<path d="M 928 148 H 948 V 61 H 964" stroke="${palette.textMuted}" stroke-width="1.5" fill="none" marker-end="url(#arrowhead)"/>`,
    `<path d="M 948 148 H 964" stroke="${palette.textMuted}" stroke-width="1.5" fill="none" marker-end="url(#arrowhead)"/>`,
    `<path d="M 948 148 V 241 H 964" stroke="${palette.textMuted}" stroke-width="1.5" fill="none" marker-end="url(#arrowhead)"/>`,
    label(600, 288, 'Rules read the whole file; findings are reported only on the changed lines', palette),
  ].join('\n  ');

  return document(1200, 310, palette, body);
}

/**
 * How taint strength changes severity. This is the single design decision that
 * most affects the noise level, so it earns a picture: the same API call is
 * scored differently depending on whether untrusted input can reach it.
 */
function severityMatrix(palette: Palette): string {
  const rows = [
    { sink: 'eval(...)', none: 'high', naming: 'high', variable: 'critical', direct: 'critical' },
    { sink: 'exec(...)', none: 'not reported', naming: 'low confidence', variable: 'critical', direct: 'critical' },
    { sink: 'fetch(url)', none: 'not reported', naming: 'low confidence', variable: 'high', direct: 'critical' },
    { sink: 'innerHTML =', none: 'not reported', naming: 'low confidence', variable: 'high', direct: 'critical' },
    { sink: 'yaml.load(...)', none: 'critical', naming: 'critical', variable: 'critical', direct: 'critical' },
  ];
  const columns = [
    { key: 'none' as const, head: 'no signal' },
    { key: 'naming' as const, head: 'name only' },
    { key: 'variable' as const, head: 'traced variable' },
    { key: 'direct' as const, head: 'reads the request' },
  ];

  const left = 24;
  const top = 104;
  const sinkWidth = 168;
  const cellWidth = 168;
  const rowHeight = 40;

  const parts: string[] = [
    `<text x="${left}" y="34" font-family="${FONT}" font-size="15" font-weight="600" ` +
      `fill="${palette.textPrimary}">Severity follows reachability, not the API name</text>`,
    `<text x="${left}" y="56" font-family="${FONT}" font-size="12" fill="${palette.textSecondary}">` +
      `How far the taint pass can trace the argument, left to right</text>`,
  ];

  columns.forEach((column, index) => {
    parts.push(
      label(left + sinkWidth + index * cellWidth + cellWidth / 2, top - 12, column.head, palette),
    );
  });

  rows.forEach((row, rowIndex) => {
    const y = top + rowIndex * rowHeight;
    parts.push(
      `<text x="${left + 4}" y="${y + 25}" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" ` +
        `font-size="12.5" fill="${palette.textPrimary}">${escapeXml(row.sink)}</text>`,
    );
    columns.forEach((column, columnIndex) => {
      const value = row[column.key];
      const x = left + sinkWidth + columnIndex * cellWidth;
      const fill = SEVERITY_FILL(value, palette);
      parts.push(
        `<rect x="${x}" y="${y + 6}" width="${cellWidth - 8}" height="${rowHeight - 12}" rx="6" ` +
          `fill="${fill.background}" stroke="${fill.border}" stroke-width="1"/>`,
        `<text x="${x + (cellWidth - 8) / 2}" y="${y + 25}" text-anchor="middle" font-family="${FONT}" ` +
          `font-size="12" fill="${fill.text}">${escapeXml(value)}</text>`,
      );
    });
  });

  parts.push(
    label(
      left,
      top + rows.length * rowHeight + 26,
      'A sink with no taint signal is either reported at its base severity or not at all, depending on the rule.',
      palette,
      'start',
    ),
  );

  return document(24 + sinkWidth + columns.length * cellWidth + 16, top + rows.length * rowHeight + 44, palette, parts.join('\n  '));
}

function SEVERITY_FILL(
  value: string,
  palette: Palette,
): { background: string; border: string; text: string } {
  if (value === 'critical') {
    return { background: palette.severityRamp.critical, border: palette.severityRamp.critical, text: palette.surfaceRaised };
  }
  if (value === 'high') {
    return { background: palette.severityRamp.high, border: palette.severityRamp.high, text: palette.surfaceRaised };
  }
  if (value === 'low confidence') {
    return { background: palette.grid, border: palette.border, text: palette.textSecondary };
  }
  return { background: 'none', border: palette.border, text: palette.textMuted };
}

function main(): void {
  mkdirSync(OUT_DIR, { recursive: true });
  const outputs: [string, (palette: Palette) => string][] = [
    ['pipeline', pipeline],
    ['severity-matrix', severityMatrix],
  ];
  for (const [name, render] of outputs) {
    for (const [theme, palette] of [['light', LIGHT], ['dark', DARK]] as const) {
      const path = `${OUT_DIR}/${name}-${theme}.svg`;
      writeFileSync(path, render(palette));
      process.stdout.write(`wrote ${path}\n`);
    }
  }
}

main();
