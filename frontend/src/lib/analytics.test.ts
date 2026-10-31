import { describe, expect, it } from 'vitest';
import type { JobView } from '../api/types';
import { completionRate, jobLatency, tokenTotals } from './analytics';

const job = (over: Partial<JobView>): JobView => ({
  job_id: 'j', status: 'succeeded', attempts: 1, max_attempts: 3, alert_id: 'A', alert_set: 'dev', memory_mode: 'off', submitted_by: 'x', enqueued_at: null, first_started_at: null, started_at: null,
  finished_at: null, not_before: null, case_id: null, error_code: null, error_detail: null, result: null, timings: null, usage: null, ...over,
});

describe('jobLatency', () => {
  it('uses only reported wall times and counts the rest as missing', () => {
    const s = jobLatency([job({ timings: { wall_seconds: 1 } }), job({ timings: { wall_seconds: 3 } }), job({}), job({ timings: {} })]);
    expect(s).toMatchObject({ n: 2, p50: 1, max: 3, missing: 2 });
  });
  it('has no statistics for no data', () => { expect(jobLatency([])).toMatchObject({ n: 0, p50: null, p95: null, max: null }); });
});

describe('tokenTotals', () => {
  it('does not count jobs without real token numbers', () => {
    const t = tokenTotals([
      job({ usage: { model_calls: 2, prompt_tokens: 1, output_tokens: 1, thinking_tokens: null, total_tokens: 100, tokens_available: true } }),
      job({ usage: { model_calls: 1, prompt_tokens: null, output_tokens: null, thinking_tokens: null, total_tokens: null, tokens_available: false } }),
      job({}),
    ]);
    expect(t).toEqual({ jobs: 3, withTokens: 1, total: 100, modelCalls: 3 });
  });
});

describe('completionRate', () => {
  it('is null when nothing finished and ignores queued/running', () => {
    expect(completionRate({ queued: 4 }).rate).toBeNull();
    expect(completionRate(undefined).rate).toBeNull();
    expect(completionRate({ succeeded: 3, failed: 1, running: 9 })).toEqual({ rate: 0.75, finished: 4 });
  });
});
