import { ApiError } from './errors';

export type QueryValue = string | number | boolean | null | undefined;

export interface RequestOptions {
  query?: Record<string, QueryValue>;
  body?: unknown;
  headers?: Record<string, string>;
  signal?: AbortSignal | undefined;
  timeoutMs?: number;
  /** The request is part of signing in or of checking the session: a 401 is an expected answer, not "your session ended", so the unauthorized handler is not called. */
  anonymous?: boolean;
}

export interface ApiResponse<T> {
  data: T;
  status: number;
  headers: Headers;
}

export interface ClientOptions {
  baseUrl: string;
  fetchImpl?: typeof fetch;
  /** Default per-request limit. */
  timeoutMs?: number;
  /** The CSRF token of the current session (from POST /auth/login or GET /auth/session), or null. Sent as X-CSRF-Token on every state-changing request. */
  getCsrfToken?: () => string | null;
  /** Called after the server refused a state-changing request for a missing or wrong CSRF token. Fetch a fresh token and return true to have the request tried once more. */
  refreshCsrf?: () => Promise<boolean>;
  /** Called when a request that is not part of signing in came back 401: the session ended (expired, revoked, signed out elsewhere). */
  onUnauthorized?: () => void;
}

export const DEFAULT_TIMEOUT_MS = 20_000;
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/** base + path + query as one string. The base may be a path ("/api") or a full URL; query values that are empty are left out. */
export function buildUrl(baseUrl: string, path: string, query?: Record<string, QueryValue>): string {
  const base = baseUrl.replace(/\/+$/, '');
  const rel = path.startsWith('/') ? path : `/${path}`;
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value === undefined || value === null || value === '') continue;
    params.set(key, String(value));
  }
  const qs = params.toString();
  return `${base}${rel}${qs ? `?${qs}` : ''}`;
}

function parseRetryAfter(value: string | null): number | null {
  if (!value) return null;
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? Math.min(Math.ceil(n), 3600) : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export class HttpClient {
  private readonly opts: ClientOptions;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: ClientOptions) {
    this.opts = opts;
    this.fetchImpl = opts.fetchImpl ?? ((...args) => globalThis.fetch(...args));
  }

  get baseUrl(): string { return this.opts.baseUrl; }

  async request<T>(method: string, path: string, options: RequestOptions = {}): Promise<ApiResponse<T>> {
    try {
      return await this.send<T>(method, path, options);
    } catch (error) {
      // A stale or missing CSRF token is refused before anything is done, so one retry with a fresh token is safe.
      if (error instanceof ApiError && error.status === 403 && error.code === 'csrf_failed' && !SAFE_METHODS.has(method) && !options.anonymous && this.opts.refreshCsrf) {
        if (await this.opts.refreshCsrf()) return this.send<T>(method, path, options);
      }
      throw error;
    }
  }

  private async send<T>(method: string, path: string, options: RequestOptions): Promise<ApiResponse<T>> {
    const { signal: outer } = options;
    if (outer?.aborted) throw new ApiError({ kind: 'aborted', message: 'Request cancelled' });

    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; controller.abort(); }, options.timeoutMs ?? this.opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
    const onOuterAbort = () => controller.abort();
    outer?.addEventListener('abort', onOuterAbort, { once: true });

    const headers: Record<string, string> = { Accept: 'application/json', ...options.headers };
    if (!SAFE_METHODS.has(method)) {
      const csrf = this.opts.getCsrfToken?.() ?? null;
      if (csrf) headers['X-CSRF-Token'] = csrf;
    }
    let body: string | undefined;
    if (options.body !== undefined) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(options.body);
    }

    try {
      let response: Response;
      try {
        const init: RequestInit = {
          method, headers, signal: controller.signal, cache: 'no-store', credentials: 'include', referrerPolicy: 'no-referrer',
        };
        if (body !== undefined) init.body = body;
        response = await this.fetchImpl(buildUrl(this.opts.baseUrl, path, options.query), init);
      } catch (error) {
        if (controller.signal.aborted) {
          if (timedOut && !outer?.aborted) throw new ApiError({ kind: 'timeout', message: 'The request timed out' });
          throw new ApiError({ kind: 'aborted', message: 'Request cancelled' });
        }
        throw new ApiError({ kind: 'network', message: error instanceof Error ? error.message : 'Network error' });
      }

      let text: string;
      try {
        text = await response.text();
      } catch {
        if (controller.signal.aborted && !(timedOut && !outer?.aborted)) throw new ApiError({ kind: 'aborted', message: 'Request cancelled' });
        throw new ApiError({ kind: timedOut ? 'timeout' : 'network', message: 'The response was interrupted', status: response.status });
      }

      let parsed: unknown = null;
      let parseFailed = false;
      if (text !== '') {
        try { parsed = JSON.parse(text); } catch { parseFailed = true; }
      }

      if (!response.ok) {
        if (response.status === 401 && !options.anonymous) this.opts.onUnauthorized?.();
        const err = !parseFailed && isRecord(parsed) && isRecord(parsed.error) ? parsed.error : {};
        throw new ApiError({
          kind: 'http',
          status: response.status,
          message: typeof err.message === 'string' ? err.message : `HTTP ${response.status}`,
          code: typeof err.code === 'string' ? err.code : `http_${response.status}`,
          ...(typeof err.reason === 'string' ? { reason: err.reason } : {}),
          ...(typeof err.field === 'string' ? { field: err.field } : {}),
          retryAfterSeconds: parseRetryAfter(response.headers.get('Retry-After')),
          body: parseFailed ? undefined : parsed,
        });
      }
      if (parseFailed) throw new ApiError({ kind: 'parse', message: 'The response was not valid JSON', status: response.status });
      return { data: parsed as T, status: response.status, headers: response.headers };
    } finally {
      clearTimeout(timer);
      outer?.removeEventListener('abort', onOuterAbort);
    }
  }
}
