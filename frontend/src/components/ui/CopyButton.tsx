import { useEffect, useRef, useState } from 'react';
import { Check, Copy } from '../icons';
import { Button } from './Button';

/** Copies a NON-SENSITIVE identifier (alert, case, job id). Reports success or failure in text, since clipboard access can be refused. */
export function CopyButton({ value, label }: { value: string; label: string }) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  const copy = async () => {
    try { await navigator.clipboard.writeText(value); setState('copied'); } catch { setState('failed'); }
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setState('idle'), 2000);
  };
  return (
    <>
      <Button variant="ghost" size="sm" className="copy-btn" icon={state === 'copied' ? Check : Copy} aria-label={`Copy ${label}`} title={`Copy ${label}`} onClick={copy} />
      <span className="visually-hidden" role="status" aria-live="polite">{state === 'copied' ? `${label} copied` : state === 'failed' ? `Could not copy ${label}` : ''}</span>
    </>
  );
}
