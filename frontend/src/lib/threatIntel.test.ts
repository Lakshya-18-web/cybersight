import { describe, expect, it } from 'vitest';
import type { ThreatIntelRecord } from '../api/types';
import { anyScore, describeRecord } from './threatIntel';

const rec = (over: Partial<ThreatIntelRecord>): ThreatIntelRecord => ({ ip: '203.0.113.9', status: 'ok', ...over });

describe('threat-intelligence record descriptions', () => {
  it('shows a real score with its report count and tone', () => {
    const v = describeRecord(rec({ reputation: { abuse_confidence_score: 90, total_reports: 12 } }));
    expect(v).toMatchObject({ tone: 'critical', hasScore: true });
    expect(v.headline).toContain('90%');
    expect(v.detail).toContain('12 reports');
    expect(describeRecord(rec({ reputation: { abuse_confidence_score: 30, total_reports: 1 } })).tone).toBe('warning');
  });
  it('shows a zero score as a score, not as missing data', () => {
    const v = describeRecord(rec({ reputation: { abuse_confidence_score: 0, total_reports: 0 } }));
    expect(v.hasScore).toBe(true);
    expect(v.tone).toBe('neutral');
  });
  it('says plainly when there is no answer, whatever the reason', () => {
    for (const status of ['disabled', 'not_applicable', 'skipped', 'unavailable', 'something_new']) {
      const v = describeRecord(rec({ status, reason: 'because', reputation: null }));
      expect(v.hasScore).toBe(false);
      expect(v.tone).toBe('neutral');
      expect(v.detail).toBe('because');
    }
  });
  it('does not treat an ok record without a numeric score as an answer', () => {
    expect(describeRecord(rec({ reputation: {} })).hasScore).toBe(false);
    expect(describeRecord(rec({ reputation: null })).hasScore).toBe(false);
  });
  it('knows whether any record had a usable score', () => {
    expect(anyScore([rec({ status: 'unavailable' })])).toBe(false);
    expect(anyScore([rec({ status: 'unavailable' }), rec({ reputation: { abuse_confidence_score: 5 } })])).toBe(true);
  });
});
