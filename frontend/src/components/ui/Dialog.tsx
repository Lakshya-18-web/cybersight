import { useEffect, useId, useRef, type ReactNode } from 'react';
import { X } from '../icons';
import { Button } from './Button';

const FOCUSABLE = 'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

interface DialogProps {
  title: string;
  onClose: () => void;
  /** While true the dialog cannot be dismissed (a request is in flight). */
  busy?: boolean;
  children: ReactNode;
  footer?: ReactNode;
}

/** A modal dialog: focus moves in, Tab stays inside, Escape and the close button dismiss it, and focus returns to what opened it. */
export function Dialog({ title, onClose, busy, children, footer }: DialogProps) {
  const titleId = useId();
  const ref = useRef<HTMLDivElement>(null);
  const closeRef = useRef(onClose);
  const busyRef = useRef(Boolean(busy));
  useEffect(() => { closeRef.current = onClose; busyRef.current = Boolean(busy); });

  useEffect(() => {
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    document.body.classList.add('dialog-open');
    const root = ref.current;
    const first = root?.querySelector<HTMLElement>('[data-autofocus]') ?? root?.querySelector<HTMLElement>('textarea, input, select') ?? root?.querySelector<HTMLElement>(FOCUSABLE);
    first?.focus();

    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !busyRef.current) { event.stopPropagation(); closeRef.current(); return; }
      if (event.key !== 'Tab' || !root) return;
      const items = Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)).filter((el) => !el.hasAttribute('hidden'));
      if (items.length === 0) { event.preventDefault(); return; }
      const firstEl = items[0] as HTMLElement;
      const lastEl = items[items.length - 1] as HTMLElement;
      if (event.shiftKey && document.activeElement === firstEl) { event.preventDefault(); lastEl.focus(); }
      else if (!event.shiftKey && document.activeElement === lastEl) { event.preventDefault(); firstEl.focus(); }
      else if (!root.contains(document.activeElement)) { event.preventDefault(); firstEl.focus(); }
    };
    document.addEventListener('keydown', onKey, true);
    return () => {
      document.removeEventListener('keydown', onKey, true);
      document.body.classList.remove('dialog-open');
      if (opener?.isConnected) opener.focus();
    };
  }, []);

  return (
    <div className="dialog-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget && !busy) onClose(); }}>
      <div className="dialog" role="dialog" aria-modal="true" aria-labelledby={titleId} ref={ref}>
        <div className="dialog-head">
          <h2 id={titleId}>{title}</h2>
          <Button variant="ghost" size="sm" icon={X} aria-label="Close dialog" onClick={onClose} disabled={Boolean(busy)} />
        </div>
        <div className="dialog-body">{children}</div>
        {footer ? <div className="dialog-foot">{footer}</div> : null}
      </div>
    </div>
  );
}
