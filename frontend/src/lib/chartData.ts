/** Pure helpers that turn data the API already returned into chart rows. Nothing here invents a value: an empty input gives an empty result. */

export interface Row { key: string; label: string; value: number }

/** {a: 3, b: 1} -> rows sorted by `order` (unknown keys last, biggest first) or, without `order`, biggest first. Zero and non-finite counts are dropped. */
export function rowsFromCounts(counts: Record<string, number> | undefined | null, order?: readonly string[], label: (key: string) => string = (k) => k): Row[] {
  if (!counts) return [];
  const rows = Object.entries(counts).filter(([, v]) => Number.isFinite(v) && v > 0).map(([key, value]) => ({ key, label: label(key), value }));
  const rank = (k: string) => { const i = order ? order.indexOf(k) : -1; return i === -1 ? Number.MAX_SAFE_INTEGER : i; };
  return rows.sort((a, b) => (order ? rank(a.key) - rank(b.key) || b.value - a.value : b.value - a.value) || a.key.localeCompare(b.key));
}

/** Count items by a string key (null/empty keys are counted under `missing`, never dropped, so the total always equals the number of items). */
export function countBy<T>(items: readonly T[], key: (item: T) => string | null | undefined, missing = 'unavailable'): Record<string, number> {
  const out: Record<string, number> = {};
  for (const item of items) {
    const k = key(item);
    const name = k === null || k === undefined || k === '' ? missing : k;
    out[name] = (out[name] ?? 0) + 1;
  }
  return out;
}

export function totalOf(rows: readonly Row[]): number { return rows.reduce((a, r) => a + r.value, 0); }

export function percent(value: number, total: number): number { return total > 0 ? Math.round((value / total) * 100) : 0; }

/** Keep the biggest `max - 1` rows and fold the rest into one "Other" row, so a chart never has more slices than it can label. */
export function topRows(rows: readonly Row[], max: number, otherLabel = 'Other'): Row[] {
  if (rows.length <= max) return [...rows];
  const sorted = [...rows].sort((a, b) => b.value - a.value);
  const head = sorted.slice(0, Math.max(1, max - 1));
  const rest = sorted.slice(head.length).reduce((a, r) => a + r.value, 0);
  return rest > 0 ? [...head, { key: '__other', label: otherLabel, value: rest }] : head;
}

export interface DayBucket { day: string; label: string; value: number }

/** Count timestamps per UTC calendar day (YYYY-MM-DD), including the empty days between the first and last one. Timestamps that are not valid dates are ignored and reported in `skipped`. */
export function bucketByDay(timestamps: readonly (string | null | undefined)[]): { buckets: DayBucket[]; skipped: number } {
  const counts = new Map<string, number>();
  let skipped = 0;
  for (const t of timestamps) {
    const ms = t ? Date.parse(t) : NaN;
    if (!Number.isFinite(ms)) { skipped += 1; continue; }
    const day = new Date(ms).toISOString().slice(0, 10);
    counts.set(day, (counts.get(day) ?? 0) + 1);
  }
  if (counts.size === 0) return { buckets: [], skipped };
  const days = [...counts.keys()].sort();
  const start = Date.parse(`${days[0]}T00:00:00Z`);
  const end = Date.parse(`${days[days.length - 1]}T00:00:00Z`);
  const buckets: DayBucket[] = [];
  for (let ms = start; ms <= end; ms += 86_400_000) {
    const day = new Date(ms).toISOString().slice(0, 10);
    buckets.push({ day, label: day.slice(5), value: counts.get(day) ?? 0 });
  }
  return { buckets, skipped };
}

/** Nearest-rank percentile of a list of numbers (0 < p <= 100). Empty input gives null: there is no such thing as the median of nothing. */
export function percentile(values: readonly number[], p: number): number | null {
  const v = values.filter((n) => Number.isFinite(n)).sort((a, b) => a - b);
  if (v.length === 0) return null;
  const rank = Math.min(v.length, Math.max(1, Math.ceil((p / 100) * v.length)));
  return v[rank - 1] ?? null;
}
