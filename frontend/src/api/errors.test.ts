import { describe, expect, it } from 'vitest';
import { ApiError, describeError, isAbort, toApiError } from './errors';

const http = (status: number, message = '', extra: Partial<ConstructorParameters<typeof ApiError>[0]> = {}) => new ApiError({ kind: 'http', status, message, code: 'x', ...extra });

describe('describeError', () => {
  it('explains network and timeout failures without blaming the user', () => {
    expect(describeError(new ApiError({ kind: 'network', message: 'Failed to fetch' })).title).toBe('Cannot reach the API');
    expect(describeError(new ApiError({ kind: 'timeout', message: 't' })).title).toMatch(/too long/);
  });
  it('uses the server message for refusals and conflicts', () => {
    expect(describeError(http(403, 'your role does not allow this')).detail).toBe('your role does not allow this');
    expect(describeError(http(409, 'the proposal is already approved')).detail).toBe('the proposal is already approved');
    expect(describeError(http(422, 'src_ip is not a valid IP address')).detail).toContain('src_ip');
  });
  it('tells the person how long to wait when rate limited', () => {
    expect(describeError(http(429, 'too many submissions; slow down', { retryAfterSeconds: 12 })).detail).toContain('12 seconds');
  });
  it('says nothing was changed when the store is down', () => {
    expect(describeError(http(503, '')).detail).toMatch(/Nothing was changed/);
  });
  it('handles anything thrown', () => {
    expect(describeError('boom').title).toBeTruthy();
    expect(toApiError(new Error('x')).kind).toBe('network');
  });
});

describe('ApiError flags', () => {
  it('classifies statuses', () => {
    expect(http(401).isUnauthorized).toBe(true);
    expect(http(403).isForbidden).toBe(true);
    expect(http(404).isNotFound).toBe(true);
    expect(http(409).isConflict).toBe(true);
    expect(http(429).isRateLimited).toBe(true);
    expect(http(503).isTransient).toBe(true);
    expect(http(422).isTransient).toBe(false);
    expect(isAbort(new ApiError({ kind: 'aborted', message: 'c' }))).toBe(true);
    expect(isAbort(http(500))).toBe(false);
  });
});
