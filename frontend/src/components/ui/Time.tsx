import { formatDateTime, formatRelative } from '../../lib/format';

/** A timestamp as relative text ("3 min ago") with the exact local time on hover and in the machine-readable attribute. */
export function Time({ value, absolute }: { value: string | null | undefined; absolute?: boolean }) {
  if (!value) return <span className="muted">—</span>;
  const exact = formatDateTime(value);
  return <time dateTime={value} title={absolute ? undefined : exact} className="nowrap">{absolute ? exact : formatRelative(value)}</time>;
}
