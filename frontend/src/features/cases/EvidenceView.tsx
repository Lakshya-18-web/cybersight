import type { EvidenceItem, HistoryEvent, MemoryHit } from '../../api/types';
import { Badge } from '../../components/ui/Badge';
import { JsonView } from '../../components/ui/JsonView';
import { Time } from '../../components/ui/Time';
import { formatScore, humanize, shortId } from '../../lib/format';

function isRecord(v: unknown): v is Record<string, unknown> { return typeof v === 'object' && v !== null && !Array.isArray(v); }

/** Statements the agents wrote about the alert, when the payload has the usual {findings:[{statement}]} shape. Everything else is shown as raw data. */
function statementsOf(payload: unknown): string[] {
  if (!isRecord(payload) || !Array.isArray(payload.findings)) return [];
  return payload.findings.flatMap((f) => (isRecord(f) && typeof f.statement === 'string' ? [f.statement] : []));
}

function EvidenceRow({ item }: { item: EvidenceItem }) {
  const statements = statementsOf(item.payload);
  const payload = isRecord(item.payload) ? item.payload : null;
  const reason = payload && typeof payload.reason === 'string' ? payload.reason : null;
  const route = payload && typeof payload.route === 'string' ? payload.route : null;
  return (
    <li data-tone={item.kind === 'specialist_finding' ? 'accent' : undefined}>
      <div className="timeline-head">
        <strong>{humanize(item.source)}</strong>
        <Badge>{humanize(item.kind)}</Badge>
        <span className="timeline-time">#{item.ordinal + 1}</span>
      </div>
      {route ? <p>Next: <strong>{humanize(route)}</strong>{reason ? <> — {reason}</> : null}</p> : null}
      {!route && reason ? <p>{reason}</p> : null}
      {statements.length ? <ul className="bullets">{statements.map((s, i) => <li key={i}>{s}</li>)}</ul> : null}
      <JsonView value={item.payload} label={`Raw data (sha256 ${shortId(item.payload_sha256, 12)}…)`} />
    </li>
  );
}

export function EvidenceView({ items }: { items: readonly EvidenceItem[] }) {
  const order = ['routing_step', 'specialist_finding', 'tool_call'];
  const sorted = [...items].sort((a, b) => (order.indexOf(a.kind) - order.indexOf(b.kind)) || a.ordinal - b.ordinal);
  return <ol className="timeline" aria-label="Evidence recorded for this case">{sorted.map((i) => <EvidenceRow key={`${i.kind}-${i.source}-${i.ordinal}`} item={i} />)}</ol>;
}

export function MemoryTable({ hits }: { hits: readonly MemoryHit[] }) {
  return (
    <div className="table-wrap">
      <table className="table" data-stack="true">
        <caption className="visually-hidden">Similar past cases retrieved from memory</caption>
        <thead><tr><th scope="col" className="num">Rank</th><th scope="col">Label</th><th scope="col" className="num">Distance</th><th scope="col">Source</th><th scope="col">Reference</th></tr></thead>
        <tbody>
          {hits.map((h) => (
            <tr key={h.memory_id}>
              <td data-label="Rank" className="num">{h.rank}</td>
              <td data-label="Label">{h.label ?? '—'}</td>
              <td data-label="Distance" className="num">{formatScore(h.distance)}</td>
              <td data-label="Source">{h.source_split ?? '—'}</td>
              <td data-label="Reference" className="mono-id">{h.source_ref ?? shortId(h.memory_id)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function HistoryTimeline({ events, showCase }: { events: readonly HistoryEvent[]; showCase?: boolean }) {
  return (
    <ol className="timeline" aria-label="Audit events">
      {events.map((e) => {
        const tone = e.event_type.includes('approved') ? 'success' : e.event_type.includes('denied') || e.event_type.includes('reject') ? 'critical' : e.event_type.includes('execution') ? 'accent' : undefined;
        return (
          <li key={e.event_id} {...(tone ? { 'data-tone': tone } : {})}>
            <div className="timeline-head">
              <strong>{humanize(e.event_type)}</strong>
              <span>by <span className="mono-id">{e.actor}</span></span>
              <span className="timeline-time"><Time value={e.occurred_at} absolute /></span>
            </div>
            <div className="muted">{humanize(e.entity_type)} <span className="mono-id">{shortId(e.entity_id, 13)}</span>{showCase && e.case_id ? <> · case <span className="mono-id">{shortId(e.case_id)}</span></> : null} · event #{e.event_id}</div>
            {e.payload && Object.keys(e.payload).length ? <JsonView value={e.payload} label="Details" /> : null}
            <div className="hash">hash {shortId(e.event_hash, 16)}… ← previous {shortId(e.prev_hash, 16)}…</div>
          </li>
        );
      })}
    </ol>
  );
}
