// Build-time settings. Only VITE_-prefixed values reach the browser bundle, so never put a secret in one.
interface ImportMetaEnv {
  readonly DEV: boolean;
  readonly MODE: string;
  /** Where the API lives, as seen by the browser. Default "/api" (same origin; a proxy removes the prefix). */
  readonly VITE_API_BASE_URL?: string;
  /** Milliseconds between job status checks. Default 2000. */
  readonly VITE_JOB_POLL_MS?: string;
  /** Milliseconds between API health checks. Default 30000. */
  readonly VITE_HEALTH_POLL_MS?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

// Stylesheet imports (Vite handles them; this only tells the type checker they exist).
declare module '*.css';
