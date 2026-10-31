import type { ReactNode } from 'react';
import { describeError } from '../../api/errors';
import { CircleAlert, CircleCheck, Info, TriangleAlert, type LucideIcon } from '../icons';
import { Button } from './Button';
import { Icon } from './Icon';

type Tone = 'critical' | 'warning' | 'success' | 'info';
const ICONS: Record<Tone, LucideIcon> = { critical: CircleAlert, warning: TriangleAlert, success: CircleCheck, info: Info };

export function Banner({ tone = 'info', title, children, actions }: { tone?: Tone; title?: string; children?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="banner" data-tone={tone} role={tone === 'critical' ? 'alert' : 'status'}>
      <Icon icon={ICONS[tone]} size={18} />
      <div className="banner-body">
        {title ? <div className="banner-title">{title}</div> : null}
        {children ? <div>{children}</div> : null}
        {actions ? <div className="banner-actions">{actions}</div> : null}
      </div>
    </div>
  );
}

export function ErrorBanner({ error, onRetry, retrying }: { error: unknown; onRetry?: () => void; retrying?: boolean }) {
  const { title, detail } = describeError(error);
  return (
    <Banner tone="critical" title={title} actions={onRetry ? <Button size="sm" onClick={onRetry} loading={Boolean(retrying)}>Retry</Button> : null}>
      {detail ? <p>{detail}</p> : null}
    </Banner>
  );
}
