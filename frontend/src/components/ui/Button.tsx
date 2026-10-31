import type { ButtonHTMLAttributes, ReactNode, Ref } from 'react';
import { LoaderCircle, type LucideIcon } from '../icons';
import { Icon } from './Icon';

interface ButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'children'> {
  variant?: 'default' | 'primary' | 'danger' | 'ghost';
  size?: 'md' | 'sm';
  icon?: LucideIcon;
  loading?: boolean;
  children?: ReactNode;
  ref?: Ref<HTMLButtonElement>;
}

export function Button({ variant = 'default', size = 'md', icon, loading, disabled, children, type = 'button', ...rest }: ButtonProps) {
  return (
    <button
      {...rest}
      type={type}
      className={['btn', rest.className].filter(Boolean).join(' ')}
      data-variant={variant}
      data-size={size}
      data-icon-only={!children && icon ? 'true' : undefined}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
    >
      {loading ? <Icon icon={LoaderCircle} spin /> : icon ? <Icon icon={icon} /> : null}
      {children}
    </button>
  );
}
