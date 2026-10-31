import type { HealthReady, ProviderHealth } from '../api/types';
import type { Tone } from './severity';

export type ServiceState = 'healthy' | 'degraded' | 'unavailable' | 'unknown';
export interface Service { key: string; name: string; state: ServiceState; detail: string }
export const STATE_TONE: Record<ServiceState, Tone> = { healthy: 'success', degraded: 'warning', unavailable: 'critical', unknown: 'neutral' };

export interface ApiHealthInput { state: 'checking' | 'ok' | 'degraded' | 'down'; detail: string; ready: HealthReady | null }

/** One row per service, each decided ONLY from what the API reported about that service. A service is never called healthy because another one answered:
 *  anything the API cannot see (workers, the sweeper) or does not test (the model) is "unknown" with the reason in words. */
export function servicesFrom(api: ApiHealthInput, providers: ProviderHealth | undefined): Service[] {
  const apiState: ServiceState = api.state === 'ok' ? 'healthy' : api.state === 'degraded' ? 'degraded' : api.state === 'down' ? 'unavailable' : 'unknown';
  const dbKnown = providers ? providers.database.reachable : api.ready ? api.ready.database : undefined;
  const brokerKnown = providers ? providers.queue.broker_ready : api.ready ? api.ready.broker : undefined;
  const backend = providers?.queue.backend ?? api.ready?.queue_backend ?? 'queue';
  const model = providers?.model;
  const ti = providers?.threat_intel.status;
  return [
    { key: 'api', name: 'API', state: apiState, detail: api.detail },
    { key: 'database', name: 'Database', state: dbKnown === undefined ? 'unknown' : dbKnown ? 'healthy' : 'unavailable', detail: dbKnown === undefined ? 'Not reported yet.' : dbKnown ? 'Reachable.' : 'Not reachable.' },
    { key: 'broker', name: 'Message broker', state: brokerKnown === undefined ? 'unknown' : brokerKnown ? 'healthy' : 'unavailable',
      detail: brokerKnown === undefined ? 'Not reported yet.' : brokerKnown ? `Reachable (${backend}).` : `Not reachable (${backend}); alerts are accepted but not queued.` },
    { key: 'worker', name: 'Worker', state: 'unknown', detail: providers?.workers.reason ? 'The API cannot see worker heartbeats; check the worker container.' : 'Not reported: the API cannot see worker heartbeats.' },
    { key: 'sweeper', name: 'Sweeper', state: 'unknown', detail: 'Not exposed by the API; check the sweeper container.' },
    { key: 'model', name: 'AI provider', state: 'unknown',
      detail: model ? `${model.mode === 'fake' ? 'Scripted stand-in model (no real model is called)' : `Mode ${model.mode}${model.configured_model ? `, ${model.configured_model}` : ''}`}; not live-checked.` : 'Not reported yet.' },
    { key: 'ti', name: 'Threat intelligence', state: 'unknown',
      detail: !ti ? 'Not reported yet.' : ti.configured === true ? 'Configured; not live-checked.' : ti.configured === false ? 'Not configured: cases are analysed without it.' : 'Unknown to the API process.' },
  ];
}
