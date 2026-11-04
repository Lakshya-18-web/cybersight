// Runtime settings read once from the build environment. Nothing here is secret: it all ships in the bundle.
function intFrom(value: string | undefined, fallback: number, min: number, max: number): number {
  const n = Number(value);
  return Number.isInteger(n) && n >= min && n <= max ? n : fallback;
}

const env = import.meta.env ?? ({} as Partial<ImportMetaEnv>);

export const config = {
  apiBaseUrl: (env.VITE_API_BASE_URL ?? '/api').replace(/\/+$/, ''),
  jobPollMs: intFrom(env.VITE_JOB_POLL_MS, 2000, 500, 60_000),
  healthPollMs: intFrom(env.VITE_HEALTH_POLL_MS, 30_000, 5_000, 600_000),
  appVersion: '0.1.0',
} as const;
