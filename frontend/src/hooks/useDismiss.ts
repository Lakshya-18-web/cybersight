import { useEffect, type RefObject } from 'react';

/** Close a popover on Escape (focus returns to its trigger), on a click outside it, or when focus moves out of it. */
export function useDismiss(open: boolean, close: () => void, container: RefObject<HTMLElement | null>, trigger: RefObject<HTMLElement | null>): void {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') { close(); trigger.current?.focus(); } };
    const onPointer = (e: MouseEvent) => { if (container.current && !container.current.contains(e.target as Node)) close(); };
    const onFocus = (e: FocusEvent) => { if (container.current && e.target instanceof Node && !container.current.contains(e.target)) close(); };
    document.addEventListener('keydown', onKey);
    document.addEventListener('mousedown', onPointer);
    document.addEventListener('focusin', onFocus);
    return () => {
      document.removeEventListener('keydown', onKey);
      document.removeEventListener('mousedown', onPointer);
      document.removeEventListener('focusin', onFocus);
    };
  }, [open, close, container, trigger]);
}
