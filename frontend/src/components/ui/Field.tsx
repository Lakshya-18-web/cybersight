import { useId, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from 'react';
import { CircleAlert } from '../icons';
import { Icon } from './Icon';

interface FieldFrame { label: string; hint?: ReactNode; error?: string | undefined; required?: boolean }

function Frame({ id, label, hint, error, required, children }: FieldFrame & { id: string; children: ReactNode }) {
  return (
    <div className="field">
      <label htmlFor={id}>{label}{required ? <span className="muted"> (required)</span> : null}</label>
      {children}
      {hint ? <div className="field-hint" id={`${id}-hint`}>{hint}</div> : null}
      {error ? <div className="field-error" id={`${id}-error`}><Icon icon={CircleAlert} size={14} /><span>{error}</span></div> : null}
    </div>
  );
}

function describedBy(id: string, hint: unknown, error: unknown): string | undefined {
  const ids = [hint ? `${id}-hint` : '', error ? `${id}-error` : ''].filter(Boolean);
  return ids.length ? ids.join(' ') : undefined;
}

export function TextField({ label, hint, error, required, id: given, ...rest }: FieldFrame & Omit<InputHTMLAttributes<HTMLInputElement>, 'required'>) {
  const auto = useId();
  const id = given ?? auto;
  return (
    <Frame id={id} label={label} hint={hint} error={error} required={required}>
      <input {...rest} id={id} className="input" aria-invalid={error ? true : undefined} aria-describedby={describedBy(id, hint, error)} aria-required={required || undefined} />
    </Frame>
  );
}

export function TextAreaField({ label, hint, error, required, id: given, ...rest }: FieldFrame & Omit<TextareaHTMLAttributes<HTMLTextAreaElement>, 'required'>) {
  const auto = useId();
  const id = given ?? auto;
  return (
    <Frame id={id} label={label} hint={hint} error={error} required={required}>
      <textarea {...rest} id={id} className="textarea" aria-invalid={error ? true : undefined} aria-describedby={describedBy(id, hint, error)} aria-required={required || undefined} />
    </Frame>
  );
}

export function SelectField({ label, hint, error, id: given, children, ...rest }: FieldFrame & SelectHTMLAttributes<HTMLSelectElement>) {
  const auto = useId();
  const id = given ?? auto;
  return (
    <Frame id={id} label={label} hint={hint} error={error}>
      <select {...rest} id={id} className="select" aria-invalid={error ? true : undefined} aria-describedby={describedBy(id, hint, error)}>{children}</select>
    </Frame>
  );
}
