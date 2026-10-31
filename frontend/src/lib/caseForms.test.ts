import { describe, expect, it } from 'vitest';
import { canResolve, NOTE_MAX, validateText } from './caseForms';

describe('analyst text validation', () => {
  it('requires text when asked to, ignoring surrounding whitespace', () => {
    expect(validateText('   ', NOTE_MAX, true, 'A note')).toBe('A note is required.');
    expect(validateText('', NOTE_MAX, false, 'A comment')).toBeUndefined();
    expect(validateText(' ok ', NOTE_MAX, true, 'A note')).toBeUndefined();
  });
  it('enforces the length limit on the raw text', () => {
    expect(validateText('a'.repeat(NOTE_MAX), NOTE_MAX, true, 'A note')).toBeUndefined();
    expect(validateText('a'.repeat(NOTE_MAX + 1), NOTE_MAX, true, 'A note')).toContain('4000');
  });
  it('allows line breaks and tabs but not other control characters', () => {
    expect(validateText('line one\nline two\ttabbed\r\n', NOTE_MAX, true, 'A note')).toBeUndefined();
    expect(validateText('bad\u0000text', NOTE_MAX, true, 'A note')).toContain('not allowed');
    expect(validateText('bad\u001btext', NOTE_MAX, true, 'A note')).toContain('not allowed');
  });
});

describe('who can resolve a case', () => {
  it('allows escalated and needs-review cases with nothing pending', () => {
    expect(canResolve('escalated', 0).allowed).toBe(true);
    expect(canResolve('needs_review', 0).allowed).toBe(true);
  });
  it('explains each refusal', () => {
    expect(canResolve('escalated', 2)).toEqual({ allowed: false, why: '2 proposed actions are still waiting for a decision. Decide them first.' });
    expect(canResolve('escalated', 1).why).toContain('1 proposed action is');
    expect(canResolve('resolved', 0).allowed).toBe(false);
    expect(canResolve('auto_closed', 0).why).toContain('automatically');
    expect(canResolve('something_new', 0).allowed).toBe(false);
  });
});
