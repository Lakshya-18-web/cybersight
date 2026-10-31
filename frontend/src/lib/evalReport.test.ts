import { describe, expect, it } from 'vitest';
import { formatRatio, summariseSensorEval } from './evalReport';

const doc = {
  set: 'synthetic-sensor-v1', synthetic: true, fake_model: true, generated_utc: '2026-10-25T06:48:18Z', limits: ['SYNTHETIC: not real'], invariant_violations: [],
  profiles: { noisy: { assumption: 'wrong on 25%', configs: { model_only: { tp: 9, fp: 1, tn: 25, fn: 1, precision: 0.9, recall: 0.9, f1: 0.9, specificity: 0.96, false_positive_rate: 0.04, false_negative_rate: 0.1, flagged_rate: 0.4, incorrect_closures_of_attacks: 1, missed_attack_scenarios: ['bot-01'] } },
    ops: { alerts: 56, simulated: true, tokens: { available: false, reason: 'fake' }, note: 'x' } } },
  provider_failure: { alerts_with_injected_outage: 13, injected_failure_fraction: 0.2, all_outage_cases_routed_to_review: true, attacks_hit_and_closed: [], confusion_full_pipeline: { tp: 1 } },
};

describe('sensor evaluation report summary', () => {
  it('copies the numbers and keeps the synthetic and fake-model labels', () => {
    const v = summariseSensorEval(doc);
    expect(v).not.toBeNull();
    expect(v?.synthetic).toBe(true);
    expect(v?.fakeModel).toBe(true);
    expect(v?.violations).toBe(0);
    const r = v?.profiles[0]?.rows[0];
    expect(r).toMatchObject({ config: 'model_only', tp: 9, fn: 1, fpr: 0.04, incorrectClosures: 1, missed: ['bot-01'] });
    expect(v?.profiles[0]?.ops.some((o) => o.label === 'tokens' && o.value === 'unavailable: fake')).toBe(true);
    expect(v?.profiles[0]?.ops.find((o) => o.label === 'note')).toBeUndefined();
    expect(v?.providerFailure).toMatchObject({ injected: 13, allToReview: true, attacksClosed: 0 });
  });
  it('does not summarise a document of another shape', () => {
    expect(summariseSensorEval(null)).toBeNull();
    expect(summariseSensorEval([])).toBeNull();
    expect(summariseSensorEval({ profiles: 3 })).toBeNull();
    expect(summariseSensorEval({ profiles: { a: 1 } })).toBeNull();
  });
  it('shows a missing number as a dash, never as zero', () => {
    expect(formatRatio(null)).toBe('—');
    expect(formatRatio(0)).toBe('0.000');
    const v = summariseSensorEval({ profiles: { p: { configs: { c: {} } } } });
    expect(v?.profiles[0]?.rows[0]?.precision).toBeNull();
  });
});
