import { useCallback, useEffect, useRef, useState } from 'react';
import { isAbort, toApiError, type ApiError } from '../api/errors';
import { createPoller, type Poller, type StopReason } from '../lib/poll';

export interface PollingOptions<T> {
  fetch: (signal: AbortSignal) => Promise<T>;
  /** Return true when there is nothing more to wait for; polling then stops by itself. */
  isDone: (data: T) => boolean;
  intervalMs: number;
  maxDurationMs?: number;
  enabled?: boolean;
}

export interface PollingState<T> {
  data: T | undefined;
  error: ApiError | undefined;
  /** True while a poller is active (it has not finished, failed for good or been stopped). */
  polling: boolean;
  stopReason: StopReason | null;
  /** Check now. If polling had stopped, this starts it again. */
  refresh: () => void;
}

/** React wrapper around createPoller. `deps` restart it (a different job id, say); unmounting stops it and cancels the request in flight. */
export function usePolling<T>(options: PollingOptions<T>, deps: readonly unknown[]): PollingState<T> {
  const [data, setData] = useState<T | undefined>(undefined);
  const [error, setError] = useState<ApiError | undefined>(undefined);
  const [polling, setPolling] = useState(false);
  const [stopReason, setStopReason] = useState<StopReason | null>(null);
  const [nonce, setNonce] = useState(0);
  const latest = useRef(options);
  const pollerRef = useRef<Poller | null>(null);

  useEffect(() => { latest.current = options; });

  const enabled = options.enabled ?? true;
  useEffect(() => {
    if (!enabled) return;
    const poller = createPoller<T>({
      fetch: (signal) => latest.current.fetch(signal),
      isDone: (d) => latest.current.isDone(d),
      intervalMs: latest.current.intervalMs,
      ...(latest.current.maxDurationMs !== undefined ? { maxDurationMs: latest.current.maxDurationMs } : {}),
      isAbort,
      isFatal: (e) => { const x = toApiError(e); return x.status === 401 || x.status === 403 || x.status === 404; },
      onData: (d) => { setData(d); setError(undefined); },
      onError: (e) => setError(toApiError(e)),
      onStop: (reason) => { setPolling(false); setStopReason(reason); },
    });
    pollerRef.current = poller;
    setStopReason(null);
    setPolling(true);
    poller.start();
    return () => { poller.stop(); pollerRef.current = null; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, enabled, nonce]);

  const refresh = useCallback(() => {
    const poller = pollerRef.current;
    if (poller?.running) poller.refresh();
    else setNonce((n) => n + 1);
  }, []);

  return { data, error, polling, stopReason, refresh };
}
