import type { ReactNode } from 'react';
import { describeError, isApiError } from '../../api/errors';
import type { Resource } from '../../hooks/useResource';
import { CircleAlert, Inbox, type LucideIcon } from '../icons';
import { Button } from './Button';
import { ErrorBanner } from './Banner';
import { Icon } from './Icon';

export function EmptyState({ icon = Inbox, title, children, action }: { icon?: LucideIcon; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="state">
      <Icon icon={icon} size={28} />
      <p className="state-title">{title}</p>
      {children ? <p>{children}</p> : null}
      {action}
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const { title, detail } = describeError(error);
  const transient = isApiError(error) && error.isTransient;
  return (
    <div className="state" role="alert">
      <Icon icon={CircleAlert} size={28} />
      <p className="state-title">{title}</p>
      {detail ? <p>{detail}</p> : null}
      {onRetry ? <Button onClick={onRetry} variant={transient ? 'primary' : 'default'}>Try again</Button> : null}
    </div>
  );
}

export function LoadingRows({ rows = 5, label = 'Loading' }: { rows?: number; label?: string }) {
  return (
    <div className="skeleton-rows" role="status" aria-live="polite">
      <span className="visually-hidden">{label}…</span>
      {Array.from({ length: rows }, (_, i) => <div key={i} className="skeleton" aria-hidden="true" />)}
    </div>
  );
}

/** Renders one of: loading placeholder, error with retry, or the data. If a reload fails while data is already on screen, the data stays and a banner explains. */
export function Async<T>({ resource, children, skeleton }: { resource: Resource<T>; children: (data: T) => ReactNode; skeleton?: ReactNode }) {
  if (resource.data === undefined) {
    if (resource.error) return <ErrorState error={resource.error} onRetry={resource.reload} />;
    return <>{skeleton ?? <LoadingRows />}</>;
  }
  return (
    <>
      {resource.error ? <ErrorBanner error={resource.error} onRetry={resource.reload} retrying={resource.refreshing} /> : null}
      {children(resource.data)}
    </>
  );
}
