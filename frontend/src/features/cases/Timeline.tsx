import type { TimelineEvent } from '../../api/types';
import { Time } from '../../components/ui/Time';
import { humanize } from '../../lib/format';

function toneOf(kind: string): 'success' | 'critical' | 'accent' | 'warning' | undefined {
  if (kind.includes('approved') || kind === 'case_resolved') return 'success';
  if (kind.includes('denied') || kind.includes('rejected') || kind.includes('refused') || kind.includes('blocked')) return 'critical';
  if (kind.includes('simulated') || kind.includes('execution')) return 'accent';
  if (kind.includes('feedback') || kind.includes('note')) return 'warning';
  return undefined;
}

/** The case's own history in plain words. Only a fixed set of non-sensitive details is ever sent by the server, so everything shown is safe to display. */
export function CaseTimeline({ events }: { events: readonly TimelineEvent[] }) {
  return (
    <ol className="timeline" aria-label="Case timeline">
      {events.map((e, i) => {
        const tone = toneOf(e.kind);
        const detail = Object.entries(e.detail ?? {}).filter(([, v]) => v !== null && v !== '');
        return (
          <li key={`${e.at}-${i}`} {...(tone ? { 'data-tone': tone } : {})}>
            <div className="timeline-head">
              <strong>{e.summary || humanize(e.kind)}</strong>
              <span>by <span className="mono-id">{e.actor}</span></span>
              <span className="timeline-time"><Time value={e.at} absolute /></span>
            </div>
            {detail.length ? <div className="muted">{detail.map(([k, v]) => `${humanize(k)}: ${String(v)}`).join(' · ')}</div> : null}
          </li>
        );
      })}
    </ol>
  );
}
