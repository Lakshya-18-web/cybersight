import type { CaseSummary } from '../api/types';
import { severityRank } from './severity';

export type SortKey = 'created' | 'severity' | 'alert';
export interface SortState { key: SortKey; dir: 'asc' | 'desc' }

/** Sorting and filtering of the rows already loaded. The API has no sort or search parameter, so this never claims to cover more than the loaded page. */
export function sortCases(items: readonly CaseSummary[], sort: SortState): CaseSummary[] {
  const sign = sort.dir === 'asc' ? 1 : -1;
  return [...items].sort((a, b) => {
    let c = 0;
    if (sort.key === 'created') c = Date.parse(a.created_at) - Date.parse(b.created_at);
    else if (sort.key === 'severity') c = severityRank(b.severity) - severityRank(a.severity); // higher severity = larger
    else c = a.alert_id.localeCompare(b.alert_id, 'en', { numeric: true });
    if (c === 0) c = a.case_id.localeCompare(b.case_id);
    return c * sign;
  });
}

export interface CaseFilter { text: string; severity: string }

export function filterCases(items: readonly CaseSummary[], filter: CaseFilter): CaseSummary[] {
  const text = filter.text.trim().toLowerCase();
  return items.filter((c) => {
    if (filter.severity && (c.severity ?? 'unknown').toLowerCase() !== filter.severity) return false;
    if (!text) return true;
    return [c.alert_id, c.attack_type ?? '', c.case_id, c.status, c.routing_decision ?? ''].some((v) => v.toLowerCase().includes(text));
  });
}

export function countBySeverity(items: readonly CaseSummary[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const c of items) {
    const key = (c.severity ?? 'unknown').toLowerCase();
    out[key] = (out[key] ?? 0) + 1;
  }
  return out;
}
