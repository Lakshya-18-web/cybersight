/** A random key for an Idempotency-Key header: 8-200 characters from [A-Za-z0-9._:-], which is what the API accepts. */
export function newIdempotencyKey(prefix = 'ui'): string {
  const c = globalThis.crypto;
  let random: string;
  if (c && typeof c.randomUUID === 'function') {
    random = c.randomUUID();
  } else if (c && typeof c.getRandomValues === 'function') {
    random = Array.from(c.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join('');
  } else {
    throw new Error('This browser cannot generate a secure random key');
  }
  return `${prefix}-${random}`;
}

export const IDEMPOTENCY_KEY_RE = /^[A-Za-z0-9._:-]{8,200}$/;

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
