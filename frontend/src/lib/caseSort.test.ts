import { describe, expect, it } from 'vitest';
import type { CaseSummary } from '../api/types';
import { countBySeverity, filterCases, sortCases } from './caseSort';

function row(over: Partial<CaseSummary>): CaseSummary {
  return {
    case_id: 'c', alert_set: 's', alert_id: 'A-1', run_name: 'r', graph_version: 'v', memory_mode: 'off', status: 'escalated', created_at: '2026-10-21T10:00:00Z', updated_at: '2026-10-21T10:00:00Z',
    verdict_status: 'ok', attack_type: 'PortScan', severity: 'medium', is_malicious: true, routing_decision: 'escalate', risk_level: 'medium', pending_actions: 0, ...over,
  };
}

const rows = [
  row({ case_id: '1', alert_id: 'A-10', severity: 'low', created_at: '2026-10-21T10:00:00Z' }),
  row({ case_id: '2', alert_id: 'A-2', severity: 'critical', created_at: '2026-10-21T12:00:00Z' }),
  row({ case_id: '3', alert_id: 'A-3', severity: null, attack_type: 'BENIGN', created_at: '2026-10-21T11:00:00Z' }),
];

describe('case sorting and filtering (page-local)', () => {
  it('sorts by time in both directions', () => {
    expect(sortCases(rows, { key: 'created', dir: 'desc' }).map((r) => r.case_id)).toEqual(['2', '3', '1']);
    expect(sortCases(rows, { key: 'created', dir: 'asc' }).map((r) => r.case_id)).toEqual(['1', '3', '2']);
  });
  it('sorts by severity with the most serious first when descending, and unknown last', () => {
    expect(sortCases(rows, { key: 'severity', dir: 'desc' }).map((r) => r.case_id)).toEqual(['2', '1', '3']);
  });
  it('sorts alert ids naturally (A-2 before A-10)', () => {
    expect(sortCases(rows, { key: 'alert', dir: 'asc' }).map((r) => r.alert_id)).toEqual(['A-2', 'A-3', 'A-10']);
  });
  it('does not change the input', () => {
    const before = rows.map((r) => r.case_id).join();
    sortCases(rows, { key: 'alert', dir: 'asc' });
    expect(rows.map((r) => r.case_id).join()).toBe(before);
  });
  it('filters by text and severity', () => {
    expect(filterCases(rows, { text: 'benign', severity: '' }).map((r) => r.case_id)).toEqual(['3']);
    expect(filterCases(rows, { text: '', severity: 'critical' }).map((r) => r.case_id)).toEqual(['2']);
    expect(filterCases(rows, { text: 'a-1', severity: '' }).map((r) => r.case_id)).toEqual(['1']);
    expect(filterCases(rows, { text: '', severity: 'unknown' }).map((r) => r.case_id)).toEqual(['3']);
  });
  it('counts by severity, with a bucket for missing values', () => {
    expect(countBySeverity(rows)).toEqual({ low: 1, critical: 1, unknown: 1 });
  });
});
