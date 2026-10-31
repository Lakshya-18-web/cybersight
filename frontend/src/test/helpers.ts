import { ApiError } from '../api/errors';

export interface Recorded { url: string; init: RequestInit }

/** A fetch stand-in for isolated tests. Every call is recorded; `handler` decides the answer. Never used outside tests. */
export function mockFetch(handler: (url: string, init: RequestInit) => Response | Promise<Response>) {
  const calls: Recorded[] = [];
  const impl = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, init: init ?? {} });
    return Promise.resolve(handler(url, init ?? {}));
  }) as typeof fetch;
  return { impl, calls };
}

export function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });
}

/** Await a promise that is expected to reject with an ApiError and return it. */
export async function captureError(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise;
  } catch (e) {
    if (e instanceof ApiError) return e;
    throw e;
  }
  throw new Error('expected the promise to reject');
}

export function headerOf(call: Recorded | undefined, name: string): string | undefined {
  const h = (call?.init.headers ?? {}) as Record<string, string>;
  return h[name];
}
