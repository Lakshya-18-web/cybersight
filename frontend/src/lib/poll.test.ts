import { describe, expect, it } from 'vitest';
import { backoffDelay, createPoller, type PollerOptions, type StopReason } from './poll';

/** A manual clock and timer so every scenario is deterministic. */
function harness<T>(over: Partial<PollerOptions<T>> & Pick<PollerOptions<T>, 'fetch' | 'isDone'>) {
  const timers = new Map<number, { fn: () => void; ms: number }>();
  let nextId = 1;
  let now = 0;
  let visible = true;
  const visListeners = new Set<() => void>();
  const stops: StopReason[] = [];
  const delays: number[] = [];
  const errors: number[] = [];
  const data: T[] = [];
  const poller = createPoller<T>({
    intervalMs: 1000,
    onData: (d) => data.push(d),
    onError: (_e, n) => errors.push(n),
    onStop: (r) => stops.push(r),
    setTimer: (fn, ms) => { const id = nextId++; timers.set(id, { fn, ms }); delays.push(ms); return id; },
    clearTimer: (h) => { timers.delete(h as number); },
    now: () => now,
    isVisible: () => visible,
    onVisible: (fn) => { visListeners.add(fn); return () => visListeners.delete(fn); },
    ...over,
  });
  const flush = () => new Promise<void>((r) => setTimeout(r, 0));
  const fire = async () => { const [id, t] = [...timers.entries()][0] ?? []; if (id === undefined || !t) throw new Error('no timer'); timers.delete(id); now += t.ms; t.fn(); await flush(); };
  return { poller, timers, stops, delays, errors, data, flush, fire, setVisible: (v: boolean) => { visible = v; visListeners.forEach((f) => f()); }, advance: (ms: number) => { now += ms; } };
}

describe('backoffDelay', () => {
  it('grows exponentially and is capped', () => {
    expect(backoffDelay(1000, 0, 30000)).toBe(1000);
    expect(backoffDelay(1000, 1, 30000)).toBe(2000);
    expect(backoffDelay(1000, 3, 30000)).toBe(8000);
    expect(backoffDelay(1000, 10, 30000)).toBe(30000);
  });
});

describe('createPoller', () => {
  it('stops by itself as soon as the work is done, and schedules nothing afterwards', async () => {
    let n = 0;
    const h = harness<number>({ fetch: async () => ++n, isDone: (d) => d >= 3 });
    h.poller.start();
    await h.flush();
    await h.fire();
    await h.fire();
    expect(h.data).toEqual([1, 2, 3]);
    expect(h.stops).toEqual(['done']);
    expect(h.timers.size).toBe(0);
    expect(h.poller.running).toBe(false);
  });

  it('never has two requests in flight', async () => {
    let inFlight = 0;
    let peak = 0;
    const releases: (() => void)[] = [];
    const h = harness<number>({
      fetch: () => new Promise<number>((resolve) => { inFlight++; peak = Math.max(peak, inFlight); releases.push(() => { inFlight--; resolve(1); }); }),
      isDone: () => false,
    });
    h.poller.start();
    h.poller.refresh();
    h.poller.refresh();
    await h.flush();
    expect(peak).toBe(1);
    releases[0]?.();
    await h.flush();
    expect(h.timers.size).toBe(1);
    h.poller.stop();
  });

  it('backs off while failing and recovers the normal interval after a success', async () => {
    let call = 0;
    const h = harness<number>({
      fetch: async () => { call++; if (call <= 2) throw new Error('down'); return call; },
      isDone: () => false,
    });
    h.poller.start();
    await h.flush();
    expect(h.delays).toEqual([2000]);
    await h.fire();
    expect(h.delays).toEqual([2000, 4000]);
    await h.fire();
    expect(h.delays).toEqual([2000, 4000, 1000]);
    expect(h.errors).toEqual([1, 2]);
    h.poller.stop();
  });

  it('gives up after too many consecutive failures', async () => {
    const h = harness<number>({ fetch: async () => { throw new Error('down'); }, isDone: () => false, maxConsecutiveFailures: 3 });
    h.poller.start();
    await h.flush();
    await h.fire();
    await h.fire();
    expect(h.stops).toEqual(['errors']);
  });

  it('stops at once on a fatal error', async () => {
    const h = harness<number>({ fetch: async () => { throw new Error('404'); }, isDone: () => false, isFatal: () => true });
    h.poller.start();
    await h.flush();
    expect(h.stops).toEqual(['fatal']);
    expect(h.timers.size).toBe(0);
  });

  it('stops after the maximum duration', async () => {
    const h = harness<number>({ fetch: async () => 1, isDone: () => false, maxDurationMs: 2500 });
    h.poller.start();
    await h.flush();
    await h.fire();
    await h.fire();
    await h.fire();
    expect(h.stops).toEqual(['timeout']);
  });

  it('stop() cancels the request in flight and nothing fires afterwards', async () => {
    let signal: AbortSignal | undefined;
    let resolve: ((n: number) => void) | undefined;
    const h = harness<number>({ fetch: (s) => new Promise<number>((r) => { signal = s; resolve = r; }), isDone: () => false });
    h.poller.start();
    await h.flush();
    h.poller.stop();
    expect(signal?.aborted).toBe(true);
    resolve?.(5);
    await h.flush();
    expect(h.data).toEqual([]);
    expect(h.timers.size).toBe(0);
    expect(h.stops).toEqual(['stopped']);
  });

  it('pauses while hidden and checks immediately when visible again', async () => {
    let calls = 0;
    const h = harness<number>({ fetch: async () => ++calls, isDone: () => false });
    h.poller.start();
    await h.flush();
    h.setVisible(false);
    await h.fire();
    expect(calls).toBe(1);
    h.setVisible(true);
    await h.flush();
    expect(calls).toBe(2);
    h.poller.stop();
  });

  it('ignores a cancelled request without counting it as a failure', async () => {
    let n = 0;
    const h = harness<number>({ fetch: async () => { n++; if (n === 1) throw new Error('aborted'); return n; }, isDone: () => false, isAbort: (e) => (e as Error).message === 'aborted' });
    h.poller.start();
    await h.flush();
    expect(h.errors).toEqual([]);
    expect(h.delays).toEqual([1000]);
    h.poller.stop();
  });

  it('can be restarted after it stopped', async () => {
    let n = 0;
    const h = harness<number>({ fetch: async () => ++n, isDone: () => true });
    h.poller.start();
    await h.flush();
    h.poller.start();
    await h.flush();
    expect(h.data).toEqual([1, 2]);
    expect(h.stops).toEqual(['done', 'done']);
  });
});
