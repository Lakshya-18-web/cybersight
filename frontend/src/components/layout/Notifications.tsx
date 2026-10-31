import { useCallback, useRef, useState } from 'react';
import { useAttention } from '../../hooks/useAttention';
import { useDismiss } from '../../hooks/useDismiss';
import { formatNumber } from '../../lib/format';
import { Link } from '../../lib/router';
import { Bell } from '../icons';
import { Icon } from '../ui/Icon';

/** The "needs attention" indicator. The number is the sum of real counts from GET /overview; the list says what each count is and links to it. */
export function Notifications() {
  const attention = useAttention();
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const close = useCallback(() => setOpen(false), []);
  useDismiss(open, close, box, trigger);
  const { total, state, items } = attention;
  const summary = state === 'unavailable' ? 'Needs attention: unavailable' : state === 'loading' ? 'Needs attention: loading' : total === 0 ? 'Nothing needs attention' : `Needs attention: ${formatNumber(total)} item${total === 1 ? '' : 's'}`;
  return (
    <div className="popover-wrap" ref={box}>
      <button ref={trigger} type="button" className="btn icon-btn" data-variant="ghost" data-size="sm" aria-expanded={open} aria-controls={open ? 'attention-panel' : undefined} aria-label={summary} title={summary}
        onClick={() => { if (!open) attention.refresh(); setOpen((v) => !v); }}>
        <Icon icon={Bell} size={16} />
        {state === 'ok' && total > 0 ? <span className="count-badge" aria-hidden="true">{total > 99 ? '99+' : total}</span> : null}
      </button>
      {open ? (
        <div className="popover" id="attention-panel" role="region" aria-label="Needs attention">
          <p className="popover-title">Needs attention</p>
          {state === 'unavailable' ? <p className="muted popover-note">The counts could not be loaded, so nothing is shown rather than a guess.</p>
            : state === 'loading' ? <p className="muted popover-note">Loading…</p>
            : items.length === 0 ? <p className="muted popover-note">No pending approvals, escalations, reviews or failed jobs.</p>
            : (
              <ul role="list" className="popover-list">
                {items.map((i) => (
                  <li key={i.key}><Link to={i.to} onClick={close} className="popover-link"><span className="num count-pill" data-tone={i.tone}>{formatNumber(i.count)}</span><span>{i.label}</span></Link></li>
                ))}
              </ul>
            )}
        </div>
      ) : null}
    </div>
  );
}
