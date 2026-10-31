import type { JobView } from '../api/types';
import { percentile } from './chartData';

export interface LatencyStats { n: number; p50: number | null; p95: number | null; max: number | null }

/** Wall-clock seconds the worker spent per job (timings.wall_seconds), over the jobs that reported it. Jobs without the number are counted in `missing`, not guessed. */
export function jobLatency(jobs: readonly JobView[]): LatencyStats & { missing: number } {
  const vals: number[] = [];
  let missing = 0;
  for (const j of jobs) {
    const v = j.timings?.wall_seconds;
    if (typeof v === 'number' && Number.isFinite(v) && v >= 0) vals.push(v); else missing += 1;
  }
  return { n: vals.length, p50: percentile(vals, 50), p95: percentile(vals, 95), max: vals.length ? Math.max(...vals) : null, missing };
}

export interface TokenStats { jobs: number; withTokens: number; total: number; modelCalls: number }

/** Token totals only from jobs whose usage says tokens were available (a real model ran). With the scripted model every job counts as "not reported". */
export function tokenTotals(jobs: readonly JobView[]): TokenStats {
  let withTokens = 0; let total = 0; let modelCalls = 0;
  for (const j of jobs) {
    const u = j.usage;
    if (!u) continue;
    if (typeof u.model_calls === 'number') modelCalls += u.model_calls;
    if (u.tokens_available !== false && typeof u.total_tokens === 'number') { withTokens += 1; total += u.total_tokens; }
  }
  return { jobs: jobs.length, withTokens, total, modelCalls };
}

/** Succeeded / (succeeded + failed + timed out) among FINISHED jobs; null when none finished (not 0%, not 100%). */
export function completionRate(counts: Record<string, number> | undefined): { rate: number | null; finished: number } {
  if (!counts) return { rate: null, finished: 0 };
  const ok = counts.succeeded ?? 0;
  const finished = ok + (counts.failed ?? 0) + (counts.timed_out ?? 0);
  return { rate: finished > 0 ? ok / finished : null, finished };
}
