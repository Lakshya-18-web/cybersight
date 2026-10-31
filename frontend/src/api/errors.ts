export type ApiErrorKind = 'network' | 'timeout' | 'aborted' | 'http' | 'parse';

export interface ApiErrorInit {
  kind: ApiErrorKind;
  message: string;
  status?: number | null;
  code?: string;
  reason?: string;
  field?: string;
  retryAfterSeconds?: number | null;
  body?: unknown;
}

/** Every failure the API layer can produce, in one shape. Server messages never contain submitted values, so they are safe to show. */
export class ApiError extends Error {
  readonly kind: ApiErrorKind;
  readonly status: number | null;
  readonly code: string;
  readonly reason: string | undefined;
  readonly field: string | undefined;
  readonly retryAfterSeconds: number | null;
  readonly body: unknown;

  constructor(init: ApiErrorInit) {
    super(init.message);
    this.name = 'ApiError';
    this.kind = init.kind;
    this.status = init.status ?? null;
    this.code = init.code ?? init.kind;
    this.reason = init.reason;
    this.field = init.field;
    this.retryAfterSeconds = init.retryAfterSeconds ?? null;
    this.body = init.body;
  }

  get isAborted(): boolean { return this.kind === 'aborted'; }
  get isUnauthorized(): boolean { return this.status === 401; }
  get isForbidden(): boolean { return this.status === 403; }
  get isNotFound(): boolean { return this.status === 404; }
  get isConflict(): boolean { return this.status === 409; }
  get isRateLimited(): boolean { return this.status === 429; }
  get isUnreachable(): boolean { return this.kind === 'network' || this.kind === 'timeout'; }
  /** A retry of the same request might succeed (outage, timeout, overload) - as opposed to a request that is simply wrong. */
  get isTransient(): boolean {
    return this.isUnreachable || this.status === 429 || this.status === 502 || this.status === 503 || this.status === 504;
  }
}

export function isApiError(value: unknown): value is ApiError {
  return value instanceof ApiError;
}

export function isAbort(value: unknown): boolean {
  return value instanceof ApiError && value.kind === 'aborted';
}

export function toApiError(value: unknown): ApiError {
  if (value instanceof ApiError) return value;
  return new ApiError({ kind: 'network', message: value instanceof Error ? value.message : 'Unexpected error' });
}

export interface ErrorText {
  title: string;
  detail: string;
}

/** A plain-language title and detail for an error banner. The detail is the server's own message when it sent one. */
export function describeError(error: unknown): ErrorText {
  const e = toApiError(error);
  switch (e.kind) {
    case 'network':
      return { title: 'Cannot reach the API', detail: 'The request did not get an answer. Check that the backend is running and that you are online, then retry.' };
    case 'timeout':
      return { title: 'The API took too long to answer', detail: 'The request was cancelled after waiting. It may still be running on the server; check before repeating a write.' };
    case 'parse':
      return { title: 'Unexpected response', detail: 'The API answered with something this console cannot read. This is a bug or a proxy in the way; the request may have succeeded.' };
    case 'aborted':
      return { title: 'Request cancelled', detail: '' };
    default:
      break;
  }
  const serverMessage = e.message && e.message !== e.code ? e.message : '';
  switch (e.status) {
    case 400: return { title: 'The API rejected the request', detail: serverMessage || 'The request was malformed.' };
    case 401: return { title: 'Sign-in required', detail: 'Your credential was not accepted or has expired. Sign in again.' };
    case 403: return { title: 'Not allowed', detail: serverMessage || 'Your role does not allow this.' };
    case 404: return { title: 'Not found', detail: serverMessage || 'That item does not exist, or has been removed.' };
    case 409: return { title: 'Conflict', detail: serverMessage || 'The item changed since you opened it.' };
    case 413: return { title: 'Request too large', detail: serverMessage || 'The request is larger than the server accepts.' };
    case 415: return { title: 'Unsupported media type', detail: serverMessage };
    case 422: return { title: 'The API could not accept this input', detail: serverMessage || 'One or more values are not valid.' };
    case 429: return { title: 'Too many requests', detail: (e.retryAfterSeconds ? `Wait ${e.retryAfterSeconds} seconds and try again. ` : 'Wait a moment and try again. ') + (serverMessage || '') };
    case 502:
    case 503:
    case 504: return { title: 'The service is not available', detail: serverMessage || 'The API or its database is not available right now. Nothing was changed by this request.' };
    default:
      return { title: e.status && e.status >= 500 ? 'The API had an error' : 'Request failed', detail: serverMessage || (e.status ? `The API answered with status ${e.status}.` : 'Unknown error.') };
  }
}
