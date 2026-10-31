import type { ThreatIntelRecord } from '../api/types';
import type { Tone } from './severity';

export interface TiView { tone: Tone; headline: string; detail: string | null; hasScore: boolean }

const STATUS_TEXT: Record<string, string> = {
  disabled: 'Not configured: no lookup was made',
  not_applicable: 'Not applicable: private or special-use address, nothing to look up',
  skipped: 'Skipped: lookups are not enabled for this kind of alert',
  unavailable: 'Unavailable: the lookup failed or was not allowed',
};

/** How one reputation record is described. A missing, failed or zero answer is shown as exactly that, never as "clean": the policy treats it as neutral and so does the page. */
export function describeRecord(r: ThreatIntelRecord): TiView {
  if (r.status === 'ok' && r.reputation && typeof r.reputation.abuse_confidence_score === 'number') {
    const score = r.reputation.abuse_confidence_score;
    const reports = typeof r.reputation.total_reports === 'number' ? r.reputation.total_reports : null;
    const tone: Tone = score >= 75 ? 'critical' : score >= 25 ? 'warning' : 'neutral';
    return { tone, headline: `Abuse confidence ${score}%`, detail: reports === null ? null : `${reports} report${reports === 1 ? '' : 's'}${r.cache_hit ? ' · from cache' : ''}`, hasScore: true };
  }
  const base = STATUS_TEXT[r.status] ?? `Status: ${r.status}`;
  return { tone: 'neutral', headline: base, detail: r.reason ?? null, hasScore: false };
}

/** Whether any record carries a usable score. Used to say "no usable answer" when every lookup failed. */
export function anyScore(records: readonly ThreatIntelRecord[]): boolean {
  return records.some((r) => describeRecord(r).hasScore);
}
