import { Fragment, type ReactNode } from 'react';

/** A definition list laid out as label | value. */
export function KeyValue({ items }: { items: readonly (readonly [string, ReactNode])[] }) {
  return (
    <dl className="kv">
      {items.map(([label, value]) => (
        <Fragment key={label}>
          <dt>{label}</dt>
          <dd>{value === null || value === undefined || value === '' ? <span className="muted">—</span> : value}</dd>
        </Fragment>
      ))}
    </dl>
  );
}
