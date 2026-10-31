import { useEffect, useRef, useState } from 'react';
import { api } from '../api';
import { isAbort, toApiError } from '../api/errors';
import type { HealthReady } from '../api/types';
import { config } from '../config';
import { createPoller } from '../lib/poll';

export type HealthState = 'checking' | 'ok' | 'degraded' | 'down';

export interface HealthInfo {
  state: HealthState;
  /** One short line for the top bar tooltip and Settings. */
  detail: string;
  ready: HealthReady | null;
  checkedAt: number | null;
}

const INITIAL: HealthInfo = { state: 'checking', detail: 'Checking the API…', ready: null, checkedAt: null };

/** Real API health from GET /health/ready (public, so it also works before sign-in). Checks every healthPollMs, pauses while the tab is hidden. */
export function useHealth(): HealthInfo & { refresh: () => void } {
  const [info, setInfo] = useState<HealthInfo>(INITIAL);
  const refreshRef = useRef<() => void>(() => undefined);

  useEffect(() => {
    const poller = createPoller<HealthReady>({
      fetch: (signal) => api.healthReady({ signal }),
      isDone: () => false,
      intervalMs: config.healthPollMs,
      maxBackoffMs: config.healthPollMs,
      maxConsecutiveFailures: Number.MAX_SAFE_INTEGER,
      isAbort,
      onData: (ready) => {
        const degraded = ready.status !== 'ok' || !ready.broker;
        setInfo({
          state: degraded ? 'degraded' : 'ok',
          detail: degraded ? `Degraded: the queue broker is not reachable (${ready.queue_backend}). Alerts are still accepted.` : `Ready: database and queue (${ready.queue_backend}) are up.`,
          ready,
          checkedAt: Date.now(),
        });
      },
      onError: (error) => {
        const e = toApiError(error);
        setInfo({
          state: 'down',
          detail: e.status === 503 ? 'Not ready: the database is not reachable.' : e.isUnreachable ? 'The API cannot be reached.' : `The API answered with an error (${e.status ?? e.kind}).`,
          ready: null,
          checkedAt: Date.now(),
        });
      },
    });
    refreshRef.current = () => poller.refresh();
    poller.start();
    return () => poller.stop();
  }, []);

  return { ...info, refresh: () => refreshRef.current() };
}
