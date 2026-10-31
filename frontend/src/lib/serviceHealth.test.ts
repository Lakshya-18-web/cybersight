import { describe, expect, it } from 'vitest';
import type { ProviderHealth } from '../api/types';
import { servicesFrom } from './serviceHealth';

const providers = (over: Partial<ProviderHealth> = {}): ProviderHealth => ({
  model: { mode: 'fake', live_calls_allowed: false, configured_model: null, status: 'not_checked', verdicts_by_status: {}, model_errors_total: 0 },
  threat_intel: { status: { configured: false }, lookups_last_24h: { by_status: {}, last_lookup_at: null, hours: 24 }, enabled_for: null },
  queue: { backend: 'celery', broker_ready: true, detail: null },
  database: { reachable: true },
  jobs: {},
  workers: { status: 'unavailable', reason: 'heartbeats are files' },
  ...over,
});
const by = (s: ReturnType<typeof servicesFrom>, k: string) => s.find((x) => x.key === k)!;

describe('servicesFrom', () => {
  it('never reports workers, the sweeper or the model as healthy: the API cannot see or does not test them', () => {
    const s = servicesFrom({ state: 'ok', detail: 'Ready', ready: { status: 'ok', database: true, broker: true, queue_backend: 'celery' } }, providers());
    expect(by(s, 'api').state).toBe('healthy');
    expect(by(s, 'database').state).toBe('healthy');
    expect(by(s, 'broker').state).toBe('healthy');
    for (const k of ['worker', 'sweeper', 'model', 'ti']) expect(by(s, k).state).toBe('unknown');
  });
  it('does not infer the database from the API answering', () => {
    const s = servicesFrom({ state: 'ok', detail: 'Ready', ready: null }, undefined);
    expect(by(s, 'database').state).toBe('unknown');
    expect(by(s, 'broker').state).toBe('unknown');
  });
  it('marks an unreachable broker and database as unavailable and a degraded API as degraded', () => {
    const s = servicesFrom({ state: 'degraded', detail: 'x', ready: { status: 'ok', database: true, broker: false, queue_backend: 'celery' } }, providers({ queue: { backend: 'celery', broker_ready: false, detail: 'down' }, database: { reachable: false } }));
    expect(by(s, 'api').state).toBe('degraded');
    expect(by(s, 'broker').state).toBe('unavailable');
    expect(by(s, 'database').state).toBe('unavailable');
  });
  it('says the API is unavailable when the health check fails', () => {
    expect(by(servicesFrom({ state: 'down', detail: 'cannot be reached', ready: null }, undefined), 'api').state).toBe('unavailable');
    expect(by(servicesFrom({ state: 'checking', detail: '', ready: null }, undefined), 'api').state).toBe('unknown');
  });
});
