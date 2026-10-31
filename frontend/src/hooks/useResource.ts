import { useCallback, useEffect, useState } from 'react';
import { isAbort, toApiError, type ApiError } from '../api/errors';

export interface Resource<T> {
  data: T | undefined;
  error: ApiError | undefined;
  /** First load: nothing to show yet. */
  loading: boolean;
  /** A reload is running while the previous data is still on screen. */
  refreshing: boolean;
  reload: () => void;
}

/** Load something when `deps` change (or reload() is called). The request is cancelled when the inputs change or the component goes away,
 *  and a cancelled request never touches state. Old data stays visible while the next load runs. */
export function useResource<T>(load: (signal: AbortSignal) => Promise<T>, deps: readonly unknown[], enabled = true): Resource<T> {
  const [data, setData] = useState<T | undefined>(undefined);
  const [error, setError] = useState<ApiError | undefined>(undefined);
  const [pending, setPending] = useState(enabled);
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    if (!enabled) { setPending(false); return; }
    const controller = new AbortController();
    setPending(true);
    load(controller.signal).then(
      (result) => {
        if (controller.signal.aborted) return;
        setData(result);
        setError(undefined);
        setPending(false);
      },
      (err: unknown) => {
        if (controller.signal.aborted || isAbort(err)) return;
        setError(toApiError(err));
        setPending(false);
      },
    );
    return () => controller.abort();
    // `load` is intentionally not a dependency: callers pass an inline function and list what it reads in `deps`.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, enabled, nonce]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);
  return { data, error, loading: pending && data === undefined, refreshing: pending && data !== undefined, reload };
}
