import { describe, expect, it } from 'vitest';
import { bucketByDay, countBy, percent, percentile, rowsFromCounts, topRows, totalOf } from './chartData';

describe('rowsFromCounts', () => {
  it('drops zero counts and follows the given order, unknown keys last', () => {
    const rows = rowsFromCounts({ low: 2, critical: 5, none: 0, odd: 1 }, ['critical', 'high', 'low']);
    expect(rows.map((r) => r.key)).toEqual(['critical', 'low', 'odd']);
  });
  it('sorts biggest first without an order and handles missing input', () => {
    expect(rowsFromCounts({ a: 1, b: 3 }).map((r) => r.key)).toEqual(['b', 'a']);
    expect(rowsFromCounts(undefined)).toEqual([]);
  });
  it('ignores non-finite values', () => {
    expect(rowsFromCounts({ a: Number.NaN, b: 2 }).map((r) => r.key)).toEqual(['b']);
  });
});

describe('countBy', () => {
  it('keeps the total equal to the number of items by naming the missing ones', () => {
    const c = countBy([{ k: 'x' }, { k: null }, { k: '' }, { k: 'x' }], (i) => i.k);
    expect(c).toEqual({ x: 2, unavailable: 2 });
    expect(Object.values(c).reduce((a, n) => a + n, 0)).toBe(4);
  });
});

describe('topRows', () => {
  it('folds the tail into Other and keeps the total', () => {
    const rows = rowsFromCounts({ a: 5, b: 4, c: 3, d: 2, e: 1 });
    const top = topRows(rows, 3);
    expect(top.map((r) => r.label)).toEqual(['a', 'b', 'Other']);
    expect(totalOf(top)).toBe(totalOf(rows));
  });
  it('leaves short lists alone', () => { expect(topRows(rowsFromCounts({ a: 1 }), 3)).toHaveLength(1); });
});

describe('percent', () => {
  it('is 0 for an empty total instead of NaN', () => { expect(percent(1, 0)).toBe(0); expect(percent(1, 4)).toBe(25); });
});

describe('bucketByDay', () => {
  it('fills the gaps between the first and last day with zeros and counts bad timestamps', () => {
    const { buckets, skipped } = bucketByDay(['2026-10-01T10:00:00Z', '2026-10-01T23:59:59Z', '2026-10-04T00:00:00Z', 'garbage', null]);
    expect(buckets.map((b) => [b.day, b.value])).toEqual([['2026-10-01', 2], ['2026-10-02', 0], ['2026-10-03', 0], ['2026-10-04', 1]]);
    expect(skipped).toBe(2);
  });
  it('returns nothing for nothing', () => { expect(bucketByDay([]).buckets).toEqual([]); });
});

describe('percentile', () => {
  it('uses the nearest rank and is null for no data', () => {
    expect(percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 50)).toBe(5);
    expect(percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 95)).toBe(10);
    expect(percentile([], 50)).toBeNull();
    expect(percentile([3], 95)).toBe(3);
  });
});
