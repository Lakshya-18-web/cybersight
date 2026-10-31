import { describe, expect, it } from 'vitest';
import { activeFilterCount, readFilters, toQuery } from './search';

const p = (s: string) => new URLSearchParams(s);

describe('alert queue filters', () => {
  it('defaults when the address bar is empty', () => {
    const f = readFilters(p(''));
    expect(f).toMatchObject({ q: '', status: '', sort: 'created_desc', limit: 25, offset: 0 });
    expect(toQuery(f)).toEqual({ limit: 25, offset: 0 });
    expect(activeFilterCount(f)).toBe(0);
  });
  it('keeps valid values and drops everything the API would not accept', () => {
    const f = readFilters(p('status=escalated&severity=bogus&risk_level=high&routing_decision=escalate&alert_set=sensor&verdict_status=x&has_pending=true&is_malicious=maybe&sort=evil&limit=7&offset=-3'));
    expect(f.status).toBe('escalated');
    expect(f.severity).toBe('');
    expect(f.verdict_status).toBe('');
    expect(f.is_malicious).toBe('');
    expect(f.sort).toBe('created_desc');
    expect(f.limit).toBe(25);
    expect(f.offset).toBe(0);
    expect(toQuery(f)).toEqual({ limit: 25, offset: 0, status: 'escalated', risk_level: 'high', routing_decision: 'escalate', alert_set: 'sensor', has_pending: 'true' });
  });
  it('limits the search text to 100 characters and trims it when sent', () => {
    expect(readFilters(p(`q=${'a'.repeat(300)}`)).q).toHaveLength(100);
    expect(toQuery(readFilters(p('q=%20%20EVE-ab%20'))).q).toBe('EVE-ab');
    expect(toQuery(readFilters(p('q=%20%20'))).q).toBeUndefined();
  });
  it('accepts dates and date-times only', () => {
    expect(readFilters(p('created_from=2026-10-24&created_to=2026-10-25T10:30')).created_from).toBe('2026-10-24');
    expect(readFilters(p('created_from=yesterday&created_to=2026-13')).created_from).toBe('');
    expect(readFilters(p('created_to=2026-10-25T10:30')).created_to).toBe('2026-10-25T10:30');
  });
  it('sends a non-default sort and counts filters but not paging or sorting', () => {
    const f = readFilters(p('sort=severity_desc&limit=50&offset=50&status=escalated&q=x'));
    expect(toQuery(f)).toMatchObject({ sort: 'severity_desc', limit: 50, offset: 50 });
    expect(activeFilterCount(f)).toBe(2);
  });
  it('rejects non-integer paging', () => {
    expect(readFilters(p('offset=1.5&limit=abc')).offset).toBe(0);
    expect(readFilters(p('offset=1e3')).offset).toBe(0);
  });
});
