import { describe, expect, it } from 'vitest';
import { IDEMPOTENCY_KEY_RE, UUID_RE, newIdempotencyKey } from './ids';

describe('idempotency keys', () => {
  it('always satisfy the API rule (8-200 characters from A-Za-z0-9._:-)', () => {
    for (let i = 0; i < 50; i++) expect(IDEMPOTENCY_KEY_RE.test(newIdempotencyKey('decision'))).toBe(true);
  });
  it('are different each time', () => {
    expect(newIdempotencyKey()).not.toBe(newIdempotencyKey());
  });
  it('recognises uuids', () => {
    expect(UUID_RE.test('976e33e5-bdd4-4dd3-a76e-0ef8ce161f2e')).toBe(true);
    expect(UUID_RE.test('976e33e5')).toBe(false);
  });
});
