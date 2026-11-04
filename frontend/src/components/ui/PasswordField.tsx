import { useId, useState, type InputHTMLAttributes, type ReactNode } from 'react';
import { CircleAlert, Eye, EyeOff } from '../icons';
import { Icon } from './Icon';

interface Props extends Omit<InputHTMLAttributes<HTMLInputElement>, 'type' | 'required'> {
  label: string;
  hint?: ReactNode;
  error?: string | undefined;
  required?: boolean;
}

/** A password input with a show / hide button. The value never leaves the input except through onChange; autocomplete is left to the password manager (pass autoComplete). */
export function PasswordField({ label, hint, error, required, id: given, ...rest }: Props) {
  const auto = useId();
  const id = given ?? auto;
  const [shown, setShown] = useState(false);
  const described = [hint ? `${id}-hint` : '', error ? `${id}-error` : ''].filter(Boolean).join(' ') || undefined;
  return (
    <div className="field">
      <label htmlFor={id}>{label}{required ? <span className="muted"> (required)</span> : null}</label>
      <div className="input-group">
        <input {...rest} id={id} className="input" type={shown ? 'text' : 'password'} spellCheck={false} autoCapitalize="none" aria-invalid={error ? true : undefined}
          aria-describedby={described} aria-required={required || undefined} />
        <button type="button" className="input-toggle" aria-pressed={shown} aria-label={shown ? `Hide ${label.toLowerCase()}` : `Show ${label.toLowerCase()}`} onClick={() => setShown((v) => !v)}>
          <Icon icon={shown ? EyeOff : Eye} size={16} />
        </button>
      </div>
      {hint ? <div className="field-hint" id={`${id}-hint`}>{hint}</div> : null}
      {error ? <div className="field-error" id={`${id}-error`}><Icon icon={CircleAlert} size={14} /><span>{error}</span></div> : null}
    </div>
  );
}
