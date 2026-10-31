import { describe, expect, it } from 'vitest';
import { formatDateTime, formatDuration, formatRelative, formatScore, humanize, pluralize, secondsBetween, shortId } from './format';

describe('format', () => {
  it('formats durations at every scale', () => {
    expect(formatDuration(0.0004)).toBe('0 ms');
    expect(formatDuration(0.25)).toBe('250 ms');
    expect(formatDuration(3.456)).toBe('3.5 s');
    expect(formatDuration(42.4)).toBe('42 s');
    expect(formatDuration(185)).toBe('3 min 05 s');
  });
  it('shows a dash for missing or invalid numbers', () => {
    expect(formatDuration(null)).toBe('—');
    expect(formatDuration(-1)).toBe('—');
    expect(formatDuration(Number.NaN)).toBe('—');
    expect(formatScore('x')).toBe('—');
    expect(formatScore(0.93041)).toBe('0.930');
  });
  it('computes relative time against an injected clock', () => {
    const now = Date.parse('2026-10-21T12:00:00Z');
    expect(formatRelative('2026-10-21T11:59:58Z', now)).toBe('just now');
    expect(formatRelative('2026-10-21T11:59:15Z', now)).toBe('45 s ago');
    expect(formatRelative('2026-10-21T11:50:00Z', now)).toBe('10 min ago');
    expect(formatRelative('2026-10-21T09:00:00Z', now)).toBe('3 h ago');
    expect(formatRelative('2026-10-19T12:00:00Z', now)).toBe('2 d ago');
    expect(formatRelative(null, now)).toBe('—');
    expect(formatRelative('not a date', now)).toBe('—');
  });
  it('formats absolute time in a given zone', () => {
    expect(formatDateTime('2026-10-21T12:00:00Z', 'UTC')).toContain('2026');
    expect(formatDateTime('garbage')).toBe('—');
  });
  it('measures seconds between timestamps', () => {
    expect(secondsBetween('2026-10-21T12:00:00Z', '2026-10-21T12:00:03.5Z')).toBe(3.5);
    expect(secondsBetween(null, '2026-10-21T12:00:00Z')).toBeNull();
    expect(secondsBetween('2026-10-21T12:00:05Z', '2026-10-21T12:00:00Z')).toBe(0);
  });
  it('humanizes enum values and shortens ids', () => {
    expect(humanize('needs_review')).toBe('Needs review');
    expect(humanize('timed_out')).toBe('Timed out');
    expect(humanize(null)).toBe('—');
    expect(shortId('976e33e5-bdd4-4dd3')).toBe('976e33e5');
    expect(pluralize(1, 'case')).toBe('1 case');
    expect(pluralize(2, 'case')).toBe('2 cases');
  });
});
