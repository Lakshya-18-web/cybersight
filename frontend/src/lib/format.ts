const DASH = '—';

function parse(value: string | null | undefined): Date | null {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** "5 Jul 2017, 14:30:00" in the viewer's time zone. */
export function formatDateTime(value: string | null | undefined, timeZone?: string): string {
  const d = parse(value);
  if (!d) return DASH;
  return new Intl.DateTimeFormat('en-GB', { dateStyle: 'medium', timeStyle: 'medium', ...(timeZone ? { timeZone } : {}) }).format(d);
}

export function formatTime(value: string | null | undefined, timeZone?: string): string {
  const d = parse(value);
  if (!d) return DASH;
  return new Intl.DateTimeFormat('en-GB', { timeStyle: 'medium', ...(timeZone ? { timeZone } : {}) }).format(d);
}

/** "3 min ago", "2 h ago", "just now"; falls back to the date after a week. `now` is injectable for tests. */
export function formatRelative(value: string | null | undefined, now: number = Date.now()): string {
  const d = parse(value);
  if (!d) return DASH;
  const seconds = Math.round((now - d.getTime()) / 1000);
  if (seconds < -60) return formatDateTime(value);
  if (seconds < 10) return 'just now';
  if (seconds < 60) return `${seconds} s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days} d ago`;
  return formatDateTime(value);
}

/** Seconds as "0.4 s", "12 s", "3 min 05 s". null/undefined -> a dash. */
export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds) || seconds < 0) return DASH;
  if (seconds < 1) return `${Math.round(seconds * 1000)} ms`;
  if (seconds < 10) return `${seconds.toFixed(1)} s`;
  if (seconds < 60) return `${Math.round(seconds)} s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return `${m} min ${String(s).padStart(2, '0')} s`;
}

/** Seconds between two ISO timestamps, or null if either is missing. */
export function secondsBetween(start: string | null | undefined, end: string | null | undefined): number | null {
  const a = parse(start);
  const b = parse(end);
  if (!a || !b) return null;
  return Math.max(0, (b.getTime() - a.getTime()) / 1000);
}

export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return DASH;
  return new Intl.NumberFormat('en-GB').format(value);
}

export function formatScore(value: unknown): string {
  return typeof value === 'number' && Number.isFinite(value) ? value.toFixed(3) : DASH;
}

/** First 8 characters of an id or hash, for tables. The full value is always available on the detail page. */
export function shortId(value: string | null | undefined, length = 8): string {
  return value ? value.slice(0, length) : DASH;
}

/** "needs_review" -> "Needs review". Unknown values are still readable. */
export function humanize(value: string | null | undefined): string {
  if (!value) return DASH;
  const text = value.replace(/[_-]+/g, ' ').trim();
  return text ? text.charAt(0).toUpperCase() + text.slice(1) : DASH;
}

export function pluralize(count: number, one: string, many = `${one}s`): string {
  return `${count} ${count === 1 ? one : many}`;
}
