import { ChevronLeft, ChevronRight } from '../icons';
import { formatNumber } from '../../lib/format';
import { Button } from './Button';

/** "Showing 26–50 of 140" with previous/next. `offset` and `limit` are the server's own paging values. */
export function Pagination({ total, limit, offset, count, onOffset, busy }: { total: number; limit: number; offset: number; count: number; onOffset: (offset: number) => void; busy?: boolean }) {
  const from = count === 0 ? 0 : offset + 1;
  const to = offset + count;
  const hasPrev = offset > 0;
  const hasNext = to < total;
  return (
    <div className="table-foot">
      <span role="status" aria-live="polite" className="num">{total === 0 ? 'No rows' : `Showing ${formatNumber(from)}–${formatNumber(to)} of ${formatNumber(total)}`}</span>
      <div className="pager">
        <Button size="sm" icon={ChevronLeft} disabled={!hasPrev || Boolean(busy)} onClick={() => onOffset(Math.max(0, offset - limit))}>Previous</Button>
        <Button size="sm" disabled={!hasNext || Boolean(busy)} onClick={() => onOffset(offset + limit)}>Next<ChevronRight size={16} aria-hidden="true" /></Button>
      </div>
    </div>
  );
}
