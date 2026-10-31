import { Link } from '../../lib/router';
import { formatNumber } from '../../lib/format';
import { percent, totalOf, type Row } from '../../lib/chartData';

/** Charts are plain SVG/HTML drawn from rows the caller computed from real API data. They use classes and attributes only (the site runs under a strict Content-Security-Policy, so no inline styles),
 *  always print the label and the number next to each mark (meaning never depends on colour), and have an accessible text equivalent. */

export type ChartRow = Row & { /** severity-like colouring (critical/high/medium/low/none) instead of the series palette */ sev?: string; to?: string };

const seriesAttr = (i: number) => String((i % 7) + 1);

export function BarList({ rows, label, empty = 'Nothing recorded yet.' }: { rows: readonly ChartRow[]; label: string; empty?: string }) {
  if (rows.length === 0) return <p className="muted chart-empty">{empty}</p>;
  const max = Math.max(1, ...rows.map((r) => r.value));
  const total = totalOf(rows);
  return (
    <ul role="list" className="barlist" aria-label={label}>
      {rows.map((r, i) => (
        <li key={r.key} className="barlist-row">
          <span className="barlist-label">{r.to ? <Link to={r.to}>{r.label}</Link> : r.label}</span>
          <svg viewBox="0 0 100 8" preserveAspectRatio="none" aria-hidden="true" focusable="false">
            <rect className="bar-track" x="0" y="0" width="100" height="8" rx="2" />
            <rect className="bar-fill" {...(r.sev ? { 'data-sev': r.sev } : { 'data-c': seriesAttr(i) })} x="0" y="0" width={Math.max(2, (r.value / max) * 100)} height="8" rx="2"><title>{`${r.label}: ${formatNumber(r.value)}`}</title></rect>
          </svg>
          <span className="barlist-value num">{formatNumber(r.value)} <span className="muted">({percent(r.value, total)}%)</span></span>
        </li>
      ))}
    </ul>
  );
}

export function Donut({ rows, label, centre }: { rows: readonly ChartRow[]; label: string; centre: string }) {
  const total = totalOf(rows);
  if (total === 0) return <p className="muted chart-empty">Nothing recorded yet.</p>;
  let offset = 0;
  const segs = rows.map((r, i) => {
    const pct = (r.value / total) * 100;
    const seg = { r, i, pct, at: offset };
    offset += pct;
    return seg;
  });
  return (
    <div className="donut">
      <svg viewBox="0 0 42 42" role="img" aria-label={`${label}: ${rows.map((r) => `${r.label} ${r.value}`).join(', ')}`} focusable="false">
        <circle className="donut-track" cx="21" cy="21" r="15.915" fill="none" strokeWidth="6" />
        {segs.map(({ r, i, pct, at }) => (
          <circle key={r.key} className="donut-seg" {...(r.sev ? { 'data-sev': r.sev } : { 'data-c': seriesAttr(i) })} cx="21" cy="21" r="15.915" fill="none" strokeWidth="6"
            strokeDasharray={`${Math.max(0, pct - 0.6)} ${100 - Math.max(0, pct - 0.6)}`} strokeDashoffset={String(25 - at)}><title>{`${r.label}: ${formatNumber(r.value)} (${percent(r.value, total)}%)`}</title></circle>
        ))}
        <text className="donut-total" x="21" y="21.5" textAnchor="middle" dominantBaseline="middle">{formatNumber(total)}</text>
        <text className="donut-sub" x="21" y="27" textAnchor="middle">{centre}</text>
      </svg>
      <ul role="list" className="donut-legend" aria-label={`${label}, legend`}>
        {segs.map(({ r, i }) => (
          <li key={r.key}>
            <svg viewBox="0 0 10 10" width="10" height="10" aria-hidden="true" focusable="false"><rect className="legend-swatch" {...(r.sev ? { 'data-sev': r.sev } : { 'data-c': seriesAttr(i) })} width="10" height="10" rx="2" /></svg>
            <span>{r.to ? <Link to={r.to}>{r.label}</Link> : r.label}</span>
            <span className="num muted">{formatNumber(r.value)} ({percent(r.value, total)}%)</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export interface ColumnPoint { key: string; label: string; value: number }

/** One column per point. A visually hidden table repeats the numbers for assistive technology. */
export function ColumnChart({ points, label, unit }: { points: readonly ColumnPoint[]; label: string; unit: string }) {
  if (points.length === 0) return <p className="muted chart-empty">Nothing to plot.</p>;
  const W = 600; const H = 140; const padL = 28; const padB = 18; const padT = 8;
  const max = Math.max(1, ...points.map((p) => p.value));
  const step = (W - padL) / points.length;
  const barW = Math.max(2, Math.min(36, step * 0.7));
  const every = Math.max(1, Math.ceil(points.length / 10));
  const y = (v: number) => padT + (H - padT - padB) * (1 - v / max);
  return (
    <figure className="columns">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`${label}: ${points.map((p) => `${p.label} ${p.value}`).join(', ')}`} focusable="false" preserveAspectRatio="xMidYMid meet">
        {[0, 0.5, 1].map((f) => (
          <g key={f}>
            <line className="grid-line" x1={padL} x2={W} y1={y(max * f)} y2={y(max * f)} />
            <text className="axis" x={padL - 4} y={y(max * f)} textAnchor="end" dominantBaseline="middle">{formatNumber(Math.round(max * f))}</text>
          </g>
        ))}
        {points.map((p, i) => {
          const x = padL + i * step + (step - barW) / 2;
          return (
            <g key={p.key}>
              <rect className="column" x={x} y={y(p.value)} width={barW} height={Math.max(p.value > 0 ? 2 : 0, H - padB - y(p.value))} rx="2"><title>{`${p.label}: ${formatNumber(p.value)} ${unit}`}</title></rect>
              {i % every === 0 ? <text className="axis" x={x + barW / 2} y={H - 4} textAnchor="middle">{p.label}</text> : null}
            </g>
          );
        })}
      </svg>
      <table className="visually-hidden"><caption>{label}</caption><thead><tr><th scope="col">Period</th><th scope="col">{unit}</th></tr></thead>
        <tbody>{points.map((p) => <tr key={p.key}><th scope="row">{p.label}</th><td>{p.value}</td></tr>)}</tbody></table>
    </figure>
  );
}
