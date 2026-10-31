import type { ReactNode } from 'react';

export function Card({ children, tone, className }: { children: ReactNode; tone?: 'critical'; className?: string }) {
  return <section className={['card', className].filter(Boolean).join(' ')} data-tone={tone}>{children}</section>;
}

export function CardHeader({ title, description, actions, level = 2 }: { title: ReactNode; description?: ReactNode; actions?: ReactNode; level?: 2 | 3 }) {
  const Heading = level === 2 ? 'h2' : 'h3';
  return (
    <div className="card-head">
      <div>
        <Heading>{title}</Heading>
        {description ? <p>{description}</p> : null}
      </div>
      {actions ? <div className="row">{actions}</div> : null}
    </div>
  );
}

export function CardBody({ children, flush }: { children: ReactNode; flush?: boolean }) {
  return <div className={flush ? 'card-body-flush' : 'card-body'}>{children}</div>;
}
