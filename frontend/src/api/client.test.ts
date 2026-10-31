import { describe, expect, it, vi } from 'vitest';
import { captureError, headerOf, jsonResponse, mockFetch } from '../test/helpers';
import { HttpClient, buildUrl } from './client';
import { createApi } from './endpoints';

describe('buildUrl', () => {
  it('joins base, path and query, dropping empty values', () => {
    expect(buildUrl('/api', '/cases', { status: 'escalated', limit: 25, offset: 0, memory_mode: '', alert_set: undefined, x: null })).toBe('/api/cases?status=escalated&limit=25&offset=0');
  });
  it('tolerates slashes at the seams and no query', () => {
    expect(buildUrl('/api/', 'health')).toBe('/api/health');
    expect(buildUrl('http://127.0.0.1:8000', '/health/ready')).toBe('http://127.0.0.1:8000/health/ready');
  });
  it('encodes values', () => {
    expect(buildUrl('/api', '/cases', { status: 'a b&c' })).toBe('/api/cases?status=a+b%26c');
  });
});

describe('HttpClient', () => {
  it('sends the bearer token and never stores credentials in the request URL', async () => {
    const { impl, calls } = mockFetch(() => jsonResponse(200, { ok: true }));
    const client = new HttpClient({ baseUrl: '/api', fetchImpl: impl, getCredentials: () => ({ kind: 'bearer', token: 'tok-123' }) });
    await client.request('GET', '/me');
    expect(headerOf(calls[0], 'Authorization')).toBe('Bearer tok-123');
    expect(calls[0]?.url).toBe('/api/me');
    expect(calls[0]?.url).not.toContain('tok-123');
    expect(calls[0]?.init.credentials).toBe('omit');
    expect(calls[0]?.init.cache).toBe('no-store');
  });
  it('uses the dev header for a dev credential', async () => {
    const { impl, calls } = mockFetch(() => jsonResponse(200, {}));
    await new HttpClient({ baseUrl: '/api', fetchImpl: impl, getCredentials: () => ({ kind: 'dev', analyst: 'alice' }) }).request('GET', '/me');
    expect(headerOf(calls[0], 'X-Dev-Analyst')).toBe('alice');
    expect(headerOf(calls[0], 'Authorization')).toBeUndefined();
  });
  it('sends JSON bodies with the right content type', async () => {
    const { impl, calls } = mockFetch(() => jsonResponse(202, { job_id: 'j' }));
    await new HttpClient({ baseUrl: '/api', fetchImpl: impl }).request('POST', '/alerts', { body: { alert: { a: 1 }, memory: 'off' } });
    expect(headerOf(calls[0], 'Content-Type')).toBe('application/json');
    expect(calls[0]?.init.body).toBe('{"alert":{"a":1},"memory":"off"}');
  });
  it('normalises an API error body, including field, reason and Retry-After', async () => {
    const { impl } = mockFetch(() => jsonResponse(422, { error: { code: 'invalid_alert', reason: 'bad_format', field: 'src_ip', message: 'src_ip is not a valid IP address' } }, { 'Retry-After': '7' }));
    const e = await captureError(new HttpClient({ baseUrl: '/api', fetchImpl: impl }).request('POST', '/alerts', { body: {} }));
    expect(e.kind).toBe('http');
    expect(e.status).toBe(422);
    expect(e.code).toBe('invalid_alert');
    expect(e.reason).toBe('bad_format');
    expect(e.field).toBe('src_ip');
    expect(e.retryAfterSeconds).toBe(7);
    expect(e.message).toContain('src_ip');
  });
  it('copes with an error that is not JSON (a proxy page, for example)', async () => {
    const { impl } = mockFetch(() => new Response('<html>Bad gateway</html>', { status: 502 }));
    const e = await captureError(new HttpClient({ baseUrl: '/api', fetchImpl: impl }).request('GET', '/cases'));
    expect(e.status).toBe(502);
    expect(e.isTransient).toBe(true);
    expect(e.message).toBe('HTTP 502');
  });
  it('reports an unreadable success body as a parse error', async () => {
    const { impl } = mockFetch(() => new Response('not json', { status: 200 }));
    const e = await captureError(new HttpClient({ baseUrl: '/api', fetchImpl: impl }).request('GET', '/cases'));
    expect(e.kind).toBe('parse');
  });
  it('reports a network failure', async () => {
    const e = await captureError(new HttpClient({ baseUrl: '/api', fetchImpl: (() => Promise.reject(new TypeError('Failed to fetch'))) as typeof fetch }).request('GET', '/cases'));
    expect(e.kind).toBe('network');
    expect(e.isUnreachable).toBe(true);
  });
  it('calls onUnauthorized only for a 401 on a credentialed request', async () => {
    const onUnauthorized = vi.fn();
    const { impl } = mockFetch(() => jsonResponse(401, { error: { code: 'unauthenticated', message: 'a valid credential is required' } }));
    await captureError(new HttpClient({ baseUrl: '/api', fetchImpl: impl, getCredentials: () => ({ kind: 'bearer', token: 't' }), onUnauthorized }).request('GET', '/cases'));
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
    await captureError(new HttpClient({ baseUrl: '/api', fetchImpl: impl, onUnauthorized }).request('GET', '/cases'));
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
  });
  it('rejects with an aborted error when the caller cancels, and does not call the API if already cancelled', async () => {
    const c = new AbortController();
    c.abort();
    const { impl, calls } = mockFetch(() => jsonResponse(200, {}));
    const e = await captureError(new HttpClient({ baseUrl: '/api', fetchImpl: impl }).request('GET', '/cases', { signal: c.signal }));
    expect(e.isAborted).toBe(true);
    expect(calls).toHaveLength(0);
  });
  it('turns a caller cancellation during the request into an aborted error', async () => {
    const c = new AbortController();
    const impl = ((_u: unknown, init?: RequestInit) => new Promise((_res, rej) => { init?.signal?.addEventListener('abort', () => rej(new DOMException('aborted', 'AbortError'))); })) as typeof fetch;
    const pending = captureError(new HttpClient({ baseUrl: '/api', fetchImpl: impl }).request('GET', '/jobs', { signal: c.signal }));
    c.abort();
    expect((await pending).isAborted).toBe(true);
  });
  it('times out a request that never answers', async () => {
    const impl = ((_u: unknown, init?: RequestInit) => new Promise((_res, rej) => { init?.signal?.addEventListener('abort', () => rej(new DOMException('aborted', 'AbortError'))); })) as typeof fetch;
    const e = await captureError(new HttpClient({ baseUrl: '/api', fetchImpl: impl, timeoutMs: 20 }).request('GET', '/jobs'));
    expect(e.kind).toBe('timeout');
    expect(e.isTransient).toBe(true);
  });
});

describe('endpoints', () => {
  it('builds the exact routes and headers the backend expects', async () => {
    const { impl, calls } = mockFetch((url) => jsonResponse(200, url.includes('/cases?') || url.includes('/jobs?') || url.includes('/approvals') ? { items: [], total: 0, limit: 1, offset: 0, next_offset: null } : {}));
    const api = createApi(new HttpClient({ baseUrl: '/api', fetchImpl: impl }));
    await api.listCases({ status: 'escalated', limit: 25, offset: 50 });
    await api.listJobs({ status: 'failed', limit: 1 });
    await api.pendingApprovals({ limit: 5 });
    await api.getCase('abc/../x');
    await api.caseEvidence('c1');
    await api.caseMemory('c1');
    await api.caseHistory('c1');
    await api.getAction('a1');
    await api.getJob('j1');
    await api.me();
    await api.health();
    await api.healthReady();
    await api.decide('a1', 'approved', 'looks right', 'decision-key-123');
    await api.simulateExecution('a1');
    await api.submitAlert({ alert: { alert_id: 'X-1' }, memory: 'off' }, 'ui-key-12345678');
    expect(calls.map((c) => `${c.init.method} ${c.url}`)).toEqual([
      'GET /api/cases?status=escalated&limit=25&offset=50',
      'GET /api/jobs?status=failed&limit=1',
      'GET /api/approvals/pending?limit=5',
      'GET /api/cases/abc%2F..%2Fx',
      'GET /api/cases/c1/evidence',
      'GET /api/cases/c1/memory',
      'GET /api/cases/c1/history',
      'GET /api/actions/a1',
      'GET /api/jobs/j1',
      'GET /api/me',
      'GET /api/health',
      'GET /api/health/ready',
      'POST /api/actions/a1/decision',
      'POST /api/actions/a1/simulate-execution',
      'POST /api/alerts',
    ]);
    expect(headerOf(calls[12], 'Idempotency-Key')).toBe('decision-key-123');
    expect(calls[12]?.init.body).toBe('{"decision":"approved","reason":"looks right"}');
    expect(headerOf(calls[14], 'Idempotency-Key')).toBe('ui-key-12345678');
  });
  it('sends no Idempotency-Key on a submission unless one is given, so the server dedupes by content', async () => {
    const { impl, calls } = mockFetch(() => jsonResponse(202, { job_id: 'j', status: 'queued', duplicate: false, dispatch: 'queued', status_url: '/jobs/j' }));
    await createApi(new HttpClient({ baseUrl: '/api', fetchImpl: impl })).submitAlert({ alert: {}, memory: 'off' });
    expect(headerOf(calls[0], 'Idempotency-Key')).toBeUndefined();
  });
  it('exposes the HTTP status of a submission so a duplicate (200) can be told from a new job (202)', async () => {
    const { impl } = mockFetch(() => jsonResponse(200, { job_id: 'j', status: 'queued', duplicate: true, dispatch: 'none', status_url: '/jobs/j' }));
    const res = await createApi(new HttpClient({ baseUrl: '/api', fetchImpl: impl })).submitAlert({ alert: {}, memory: 'off' }, 'ui-key-12345678');
    expect(res.httpStatus).toBe(200);
    expect(res.duplicate).toBe(true);
  });
});
