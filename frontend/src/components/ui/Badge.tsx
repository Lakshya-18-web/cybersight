import type { ReactNode } from 'react';
import { humanize } from '../../lib/format';
import { actionTone, caseStatusTone, jobTone, routingTone, severityTone, type Tone } from '../../lib/severity';

export function Badge({ tone = 'neutral', solid, children }: { tone?: Tone; solid?: boolean; children: ReactNode }) {
  return <span className="badge" data-tone={tone} data-solid={solid ? 'true' : undefined}>{children}</span>;
}

/** Severity is always spelled out; critical is filled, high is outlined, so the two are distinguishable without colour. */
export function SeverityBadge({ severity }: { severity: string | null | undefined }) {
  if (!severity) return <span className="muted">—</span>;
  const s = severity.toLowerCase();
  return (
    <Badge tone={severityTone(s)} solid={s === 'critical'}>
      <span className="sev-dot" aria-hidden="true" />{humanize(s)}
    </Badge>
  );
}

export function CaseStatusBadge({ status }: { status: string | null | undefined }) { return <Badge tone={caseStatusTone(status)}>{humanize(status)}</Badge>; }
export function RoutingBadge({ decision }: { decision: string | null | undefined }) { return decision ? <Badge tone={routingTone(decision)}>{humanize(decision)}</Badge> : <span className="muted">—</span>; }
export function JobStatusBadge({ status }: { status: string | null | undefined }) { return <Badge tone={jobTone(status)}>{humanize(status)}</Badge>; }
export function ActionStateBadge({ state }: { state: string | null | undefined }) { return <Badge tone={actionTone(state)}>{humanize(state)}</Badge>; }
export function RiskBadge({ risk }: { risk: string | null | undefined }) { return risk ? <Badge tone={severityTone(risk)}>{humanize(risk)}</Badge> : <span className="muted">—</span>; }
