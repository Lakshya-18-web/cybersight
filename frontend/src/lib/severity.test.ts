import { describe, expect, it } from 'vitest';
import { actionTone, caseStatusTone, jobTone, routingTone, severityRank, severityTone } from './severity';

describe('severity and status tones', () => {
  it('ranks severities from most to least serious and unknown last', () => {
    const order = ['critical', 'high', 'medium', 'low', 'none', 'weird'].map(severityRank);
    expect(order).toEqual([0, 1, 2, 3, 4, 5]);
    expect(severityRank(null)).toBe(5);
    expect(severityRank('HIGH')).toBe(1);
  });
  it('maps severity to a semantic tone', () => {
    expect(severityTone('critical')).toBe('critical');
    expect(severityTone('high')).toBe('critical');
    expect(severityTone('medium')).toBe('warning');
    expect(severityTone('low')).toBe('info');
    expect(severityTone('none')).toBe('success');
    expect(severityTone('???')).toBe('neutral');
  });
  it('maps statuses', () => {
    expect(caseStatusTone('escalated')).toBe('critical');
    expect(caseStatusTone('needs_review')).toBe('warning');
    expect(routingTone('escalate')).toBe('critical');
    expect(jobTone('failed')).toBe('critical');
    expect(jobTone('timed_out')).toBe('warning');
    expect(jobTone('succeeded')).toBe('success');
    expect(actionTone('pending')).toBe('warning');
    expect(actionTone('approved')).toBe('success');
  });
});
