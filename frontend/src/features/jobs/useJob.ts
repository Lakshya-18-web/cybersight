import { api } from '../../api';
import { TERMINAL_JOB_STATUSES, type JobView } from '../../api/types';
import { config } from '../../config';
import { usePolling } from '../../hooks/usePolling';

export const JOB_WATCH_LIMIT_MS = 10 * 60 * 1000;

/** Follow one job until it succeeds, fails or times out. Checks every VITE_JOB_POLL_MS, one request at a time, and stops by itself. */
export function useJob(jobId: string | null) {
  return usePolling<JobView>(
    {
      fetch: (signal) => api.getJob(jobId as string, { signal }),
      isDone: (job) => TERMINAL_JOB_STATUSES.includes(job.status),
      intervalMs: config.jobPollMs,
      maxDurationMs: JOB_WATCH_LIMIT_MS,
      enabled: jobId !== null,
    },
    [jobId],
  );
}
