import { ALERT_SETS, RISK_LEVELS, ROUTING_DECISIONS, SEARCH_SORTS, VERDICT_STATUSES, CASE_STATUSES } from '../api/types';
import type { SearchQuery } from '../api/endpoints';
import { SEVERITY_ORDER } from './severity';

/** The alert queue's filters. They live in the address bar, so a filtered view can be bookmarked or shared, and every value is checked against what the API accepts: a hand-edited URL cannot send anything else. */
export interface AlertFilters {
  q: string;
  status: string;
  severity: string;
  risk_level: string;
  routing_decision: string;
  alert_set: string;
  verdict_status: string;
  has_pending: string;
  is_malicious: string;
  created_from: string;
  created_to: string;
  sort: string;
  limit: number;
  offset: number;
}

export const PAGE_SIZES = [25, 50, 100] as const;
export const DEFAULT_SORT = 'created_desc';
export const Q_MAX = 100;
const BOOL = ['true', 'false'] as const;
const DATE_RE = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2})?)?$/;

function oneOf(value: string | null, allowed: readonly string[]): string {
  return value !== null && allowed.includes(value) ? value : '';
}
function intParam(value: string | null, fallback: number, min: number): number {
  if (value === null || !/^\d{1,9}$/.test(value)) return fallback;
  const n = Number(value);
  return n >= min ? n : fallback;
}

export function readFilters(params: URLSearchParams): AlertFilters {
  const limit = intParam(params.get('limit'), 25, 1);
  const date = (name: string) => { const v = params.get(name) ?? ''; return DATE_RE.test(v) ? v : ''; };
  return {
    q: (params.get('q') ?? '').slice(0, Q_MAX),
    status: oneOf(params.get('status'), CASE_STATUSES),
    severity: oneOf(params.get('severity'), SEVERITY_ORDER),
    risk_level: oneOf(params.get('risk_level'), RISK_LEVELS),
    routing_decision: oneOf(params.get('routing_decision'), ROUTING_DECISIONS),
    alert_set: oneOf(params.get('alert_set'), ALERT_SETS),
    verdict_status: oneOf(params.get('verdict_status'), VERDICT_STATUSES),
    has_pending: oneOf(params.get('has_pending'), BOOL),
    is_malicious: oneOf(params.get('is_malicious'), BOOL),
    created_from: date('created_from'),
    created_to: date('created_to'),
    sort: oneOf(params.get('sort'), SEARCH_SORTS) || DEFAULT_SORT,
    limit: (PAGE_SIZES as readonly number[]).includes(limit) ? limit : 25,
    offset: intParam(params.get('offset'), 0, 0),
  };
}

/** Only non-empty filters are sent; the server's defaults apply to the rest. */
export function toQuery(f: AlertFilters): SearchQuery {
  const out: SearchQuery = { limit: f.limit, offset: f.offset };
  const text = f.q.trim();
  if (text) out.q = text;
  for (const k of ['status', 'severity', 'risk_level', 'routing_decision', 'alert_set', 'verdict_status', 'has_pending', 'is_malicious', 'created_from', 'created_to'] as const) {
    if (f[k]) out[k] = f[k];
  }
  if (f.sort !== DEFAULT_SORT) out.sort = f.sort;
  return out;
}

/** How many filters (not paging or sorting) are narrowing the list. */
export function activeFilterCount(f: AlertFilters): number {
  return (['q', 'status', 'severity', 'risk_level', 'routing_decision', 'alert_set', 'verdict_status', 'has_pending', 'is_malicious', 'created_from', 'created_to'] as const)
    .filter((k) => (k === 'q' ? f.q.trim() !== '' : f[k] !== '')).length;
}

/** A date input gives "2026-10-24"; the API reads that as the start of the day (inclusive for "from", exclusive for "to"). */
export function isDate(value: string): boolean { return DATE_RE.test(value); }

export const FILTER_PARAMS = ['q', 'status', 'severity', 'risk_level', 'routing_decision', 'alert_set', 'verdict_status', 'has_pending', 'is_malicious', 'created_from', 'created_to', 'sort', 'limit', 'offset'] as const;
