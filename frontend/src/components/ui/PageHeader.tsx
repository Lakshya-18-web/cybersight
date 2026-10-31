import type { ReactNode } from 'react';
import { Breadcrumbs, type Crumb } from './Breadcrumbs';

export function PageHeader({ title, description, actions, crumbs }: { title: string; description?: ReactNode; actions?: ReactNode; crumbs?: readonly Crumb[] }) {
  return (
    <header className="page-header">
      <div>
        {crumbs && crumbs.length > 1 ? <Breadcrumbs items={crumbs} /> : null}
        <h1>{title}</h1>
        {description ? <div className="page-desc">{description}</div> : null}
      </div>
      {actions ? <div className="page-actions">{actions}</div> : null}
    </header>
  );
}
