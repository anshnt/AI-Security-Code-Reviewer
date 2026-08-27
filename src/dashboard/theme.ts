import type { Category, Severity } from '../analysis/types';

/**
 * Chart palette.
 *
 * Every value here was checked with a palette validator rather than chosen by
 * eye, and the choices that look surprising are the ones the checks forced:
 *
 *   Severity uses a single-hue blue ramp, not red-amber-green. Severity is an
 *   ordered scale, so a sequential ramp is the correct encoding - and the
 *   traffic-light version fails outright: `#d03b3b` against `#0ca30c` measures
 *   a colour difference of 4.1 under deuteranopia, which is to say the most
 *   common form of colour blindness cannot separate "critical" from "low".
 *   Severity names are printed on every mark regardless, so colour never
 *   carries the meaning alone.
 *
 *   Introduced-vs-resolved uses blue and orange, with polarity carried by
 *   geometry: introduced bars rise from the zero baseline, resolved bars fall
 *   below it. Position does the work that red-versus-green cannot do safely.
 *
 *   Dark mode is a separate set of steps validated against the dark surface,
 *   not an inversion of the light one. On a dark surface the ramp runs the
 *   other way, so the most severe band is the highest-contrast one in both
 *   themes.
 */

export interface Palette {
  surface: string;
  surfaceRaised: string;
  border: string;
  grid: string;
  textPrimary: string;
  textSecondary: string;
  textMuted: string;
  /** Findings, and the "introduced" arm of the flow chart. */
  series1: string;
  /** The "resolved" arm of the flow chart. */
  series2: string;
  /** Critical to info, most severe first. */
  severityRamp: Record<Severity, string>;
}

export const LIGHT: Palette = {
  surface: '#fcfcfb',
  surfaceRaised: '#ffffff',
  border: '#e6e5e1',
  grid: '#efeeea',
  textPrimary: '#0b0b0b',
  textSecondary: '#52514e',
  textMuted: '#7a7873',
  series1: '#2a78d6',
  series2: '#eb6834',
  severityRamp: {
    critical: '#104281',
    high: '#1c5cab',
    medium: '#2a78d6',
    low: '#5598e7',
    info: '#86b6ef',
  },
};

export const DARK: Palette = {
  surface: '#1a1a19',
  surfaceRaised: '#232322',
  border: '#383835',
  grid: '#2b2b29',
  textPrimary: '#ffffff',
  textSecondary: '#c3c2b7',
  textMuted: '#95948b',
  series1: '#3987e5',
  series2: '#d95926',
  severityRamp: {
    critical: '#b7d3f6',
    high: '#86b6ef',
    medium: '#5598e7',
    low: '#256abf',
    info: '#184f95',
  },
};

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export const CATEGORY_ORDER: Category[] = [
  'sql-injection',
  'authentication',
  'secrets',
  'dependencies',
  'authorization',
  'dangerous-api',
];
