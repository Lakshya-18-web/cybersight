export type Tone = 'neutral' | 'critical' | 'warning' | 'success' | 'info' | 'accent' | 'violet';

/** Highest first. Anything the API sends that is not listed sorts last and renders as plain text. */
export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'none'] as const;

export function severityRank(severity: string | null | undefined): number {
  const i = SEVERITY_ORDER.indexOf((severity ?? '').toLowerCase() as (typeof SEVERITY_ORDER)[number]);
  return i === -1 ? SEVERITY_ORDER.length : i;
}

/** critical and high both use the critical colour (high is shown outlined, critical solid, and the text always says which); medium warns; low informs; none is calm. */
export function severityTone(severity: string | null | undefined): Tone {
  switch ((severity ?? '').toLowerCase()) {
    case 'critical':
    case 'high': return 'critical';
    case 'medium': return 'warning';
    case 'low': return 'info';
    case 'none': return 'success';
    default: return 'neutral';
  }
}

export function caseStatusTone(status: string | null | undefined): Tone {
  switch (status) {
    case 'escalated': return 'critical';
    case 'needs_review': return 'warning';
    case 'resolved': return 'success';
    case 'auto_closed': return 'neutral';
    default: return 'neutral';
  }
}

export function routingTone(decision: string | null | undefined): Tone {
  switch (decision) {
    case 'escalate': return 'critical';
    case 'needs_review': return 'warning';
    case 'auto_close': return 'neutral';
    default: return 'neutral';
  }
}

export function jobTone(status: string | null | undefined): Tone {
  switch (status) {
    case 'succeeded': return 'success';
    case 'running': return 'info';
    case 'failed': return 'critical';
    case 'timed_out': return 'warning';
    case 'queued': return 'neutral';
    default: return 'neutral';
  }
}

export function actionTone(state: string | null | undefined): Tone {
  switch (state) {
    case 'pending': return 'warning';
    case 'approved': return 'success';
    case 'rejected': return 'neutral';
    default: return 'neutral';
  }
}
