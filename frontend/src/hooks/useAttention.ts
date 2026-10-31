import { useCallback, useEffect, useState } from 'react';
import { api } from '../api';
import { isAbort } from '../api/errors';
import type { Overview } from '../api/types';
import { config } from '../config';

export interface AttentionItem { key: string; label: string; count: number; to: string; tone: 'critical' | 'warning' }
export interface Attention { items: AttentionItem[]; total: number; state: 'loading' | 'ok' | 'unavailable'; refresh: () => void }

/** What currently needs a person, computed from the real GET /overview counts. Nothing is invented: if the request fails the indicator says unavailable and shows no number.
 *  Checked once on mount, whenever the menu is opened, and at the same slow interval as the health check (never while the tab is hidden). */
export function itemsFrom(ov: Overview): AttentionItem[] {
  const list: AttentionItem[] = [
    { key: 'approvals', label: 'Proposed actions awaiting approval', count: ov.pending_actions, to: '/playbooks', tone: 'warning' },
    { key: 'escalated', label: 'Escalated cases', count: ov.by_status.escalated ?? 0, to: '/alerts?status=escalated', tone: 'critical' },
    { key: 'review', label: 'Cases that need review', count: ov.by_status.needs_review ?? 0, to: '/alerts?status=needs_review', tone: 'warning' },
    { key: 'failed', label: 'Failed or timed-out jobs', count: (ov.jobs.failed ?? 0) + (ov.jobs.timed_out ?? 0), to: '/jobs?status=failed', tone: 'critical' },
  ];
  return list.filter((i) => i.count > 0);
}

export function useAttention(): Attention {
  const [ov, setOv] = useState<Overview | null>(null);
  const [state, setState] = useState<Attention['state']>('loading');
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    api.overview({ signal: controller.signal }).then(
      (data) => { if (!controller.signal.aborted) { setOv(data); setState('ok'); } },
      (error: unknown) => { if (!controller.signal.aborted && !isAbort(error)) { setOv(null); setState('unavailable'); } },
    );
    return () => controller.abort();
  }, [nonce]);

  useEffect(() => {
    const id = window.setInterval(() => { if (!document.hidden) setNonce((n) => n + 1); }, config.healthPollMs);
    return () => window.clearInterval(id);
  }, []);

  const items = ov ? itemsFrom(ov) : [];
  const refresh = useCallback(() => setNonce((n) => n + 1), []);
  return { items, total: items.reduce((a, i) => a + i.count, 0), state, refresh };
}
