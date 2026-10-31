/** A polling engine with the guarantees the UI relies on:
 *  - one request at a time: the next check is scheduled only after the previous one finished (no overlap, no pile-up);
 *  - stops by itself when isDone() says the work is finished, on a fatal error, after maxDurationMs, or after too many failures in a row;
 *  - slows down (exponential back-off) while the API is failing, and speeds back up after a success;
 *  - pauses while the tab is hidden and checks immediately when it becomes visible again;
 *  - stop() cancels the request in flight and any scheduled check, and nothing can fire afterwards.
 */
export type StopReason = 'done' | 'fatal' | 'timeout' | 'errors' | 'stopped';

export interface PollerOptions<T> {
  fetch: (signal: AbortSignal) => Promise<T>;
  isDone: (data: T) => boolean;
  intervalMs: number;
  maxBackoffMs?: number;
  maxDurationMs?: number;
  maxConsecutiveFailures?: number;
  isFatal?: (error: unknown) => boolean;
  isAbort?: (error: unknown) => boolean;
  onData?: (data: T) => void;
  onError?: (error: unknown, consecutiveFailures: number) => void;
  onStop?: (reason: StopReason) => void;
  // injectable for tests
  setTimer?: (fn: () => void, ms: number) => unknown;
  clearTimer?: (handle: unknown) => void;
  now?: () => number;
  isVisible?: () => boolean;
  onVisible?: (fn: () => void) => () => void;
}

export interface Poller {
  start(): void;
  stop(): void;
  /** Check now instead of waiting (no effect while a check is running or after stopping). */
  refresh(): void;
  readonly running: boolean;
}

export function backoffDelay(intervalMs: number, failures: number, maxBackoffMs: number): number {
  if (failures <= 0) return intervalMs;
  return Math.min(maxBackoffMs, intervalMs * 2 ** failures);
}

export function createPoller<T>(opts: PollerOptions<T>): Poller {
  const setTimer = opts.setTimer ?? ((fn, ms) => setTimeout(fn, ms));
  const clearTimer = opts.clearTimer ?? ((h) => clearTimeout(h as ReturnType<typeof setTimeout>));
  const now = opts.now ?? (() => Date.now());
  const isVisible = opts.isVisible ?? (() => typeof document === 'undefined' || !document.hidden);
  const onVisible = opts.onVisible ?? ((fn) => {
    if (typeof document === 'undefined') return () => undefined;
    document.addEventListener('visibilitychange', fn);
    return () => document.removeEventListener('visibilitychange', fn);
  });
  const maxBackoff = opts.maxBackoffMs ?? 30_000;
  const maxFailures = opts.maxConsecutiveFailures ?? 8;

  let running = false;
  let inFlight: AbortController | null = null;
  let timer: unknown = null;
  let waitingForVisible = false;
  let failures = 0;
  let startedAt = 0;
  let unsubscribe: (() => void) | null = null;

  const stopWith = (reason: StopReason) => {
    if (!running) return;
    running = false;
    if (timer !== null) { clearTimer(timer); timer = null; }
    inFlight?.abort();
    inFlight = null;
    unsubscribe?.();
    unsubscribe = null;
    opts.onStop?.(reason);
  };

  const schedule = (delay: number) => {
    if (!running) return;
    if (timer !== null) clearTimer(timer);
    timer = setTimer(() => { timer = null; void tick(); }, delay);
  };

  const tick = async (): Promise<void> => {
    if (!running || inFlight) return;
    if (opts.maxDurationMs !== undefined && now() - startedAt >= opts.maxDurationMs) { stopWith('timeout'); return; }
    if (!isVisible()) { waitingForVisible = true; return; }
    waitingForVisible = false;
    const controller = new AbortController();
    inFlight = controller;
    try {
      const data = await opts.fetch(controller.signal);
      if (controller.signal.aborted || !running) return;
      inFlight = null;
      failures = 0;
      opts.onData?.(data);
      if (!running) return;
      if (opts.isDone(data)) { stopWith('done'); return; }
      schedule(opts.intervalMs);
    } catch (error) {
      if (controller.signal.aborted || !running) return;
      inFlight = null;
      if (opts.isAbort?.(error)) { schedule(opts.intervalMs); return; }
      failures += 1;
      opts.onError?.(error, failures);
      if (!running) return;
      if (opts.isFatal?.(error)) { stopWith('fatal'); return; }
      if (failures >= maxFailures) { stopWith('errors'); return; }
      schedule(backoffDelay(opts.intervalMs, failures, maxBackoff));
    }
  };

  return {
    start() {
      if (running) return;
      running = true;
      failures = 0;
      startedAt = now();
      unsubscribe = onVisible(() => { if (running && waitingForVisible && isVisible()) void tick(); });
      void tick();
    },
    stop() { stopWith('stopped'); },
    refresh() {
      if (!running || inFlight) return;
      if (timer !== null) { clearTimer(timer); timer = null; }
      void tick();
    },
    get running() { return running; },
  };
}
