import { useState } from 'react';
import { api } from '../../api';
import { toApiError } from '../../api/errors';
import type { DecisionResult, ProposedAction } from '../../api/types';
import { usePermissions } from '../../auth/AuthContext';
import { Check, Play, X } from '../../components/icons';
import { ActionStateBadge } from '../../components/ui/Badge';
import { Banner, ErrorBanner } from '../../components/ui/Banner';
import { Button } from '../../components/ui/Button';
import { JsonView } from '../../components/ui/JsonView';
import { KeyValue } from '../../components/ui/KeyValue';
import { Time } from '../../components/ui/Time';
import { useResource } from '../../hooks/useResource';
import { formatDateTime, humanize } from '../../lib/format';
import { DecisionDialog } from './DecisionDialog';

/** One proposed action with its decision history and the controls the signed-in role is allowed to use (the API decides what is allowed; /me only tells us what to offer). */
export function ActionCard({ action: fromCase, onChanged }: { action: ProposedAction; onChanged: () => void }) {
  const { decide } = usePermissions();
  // The decision's own answer is shown at once; once the case has been reloaded and no longer says "pending", the case's copy takes over again.
  const [decided, setDecided] = useState<ProposedAction | null>(null);
  const action = decided && fromCase.state === 'pending' ? decided : fromCase;
  const [dialog, setDialog] = useState<'approved' | 'rejected' | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [simulating, setSimulating] = useState(false);
  const [simError, setSimError] = useState<unknown>(null);

  // The decision and execution records are not part of the case view, so they are read from the action itself once it has been decided.
  const detail = useResource((signal) => api.getAction(action.action_id, { signal }), [action.action_id, action.state], action.state !== 'pending');
  const execution = detail.data?.execution ?? null;

  const onDecided = (result: DecisionResult) => {
    setDialog(null);
    setDecided(result.action);
    setNotice(result.replayed ? 'That decision had already been recorded; nothing was changed.' : `Decision recorded: ${humanize(result.action.state).toLowerCase()}.`);
    onChanged();
  };

  const simulate = async () => {
    setSimulating(true);
    setSimError(null);
    try {
      const res = await api.simulateExecution(action.action_id);
      if (res.outcome === 'already_simulated') setNotice('A simulated execution had already been recorded.');
      detail.reload();
    } catch (e) {
      setSimError(toApiError(e));
    } finally {
      setSimulating(false);
    }
  };

  const params = action.parameters && Object.keys(action.parameters).length ? action.parameters : null;
  return (
    <article className="action-card" aria-label={`${humanize(action.action_type)} for ${action.target ?? 'no target'}`}>
      <div className="row-between">
        <div className="row">
          <h3>{humanize(action.action_type)}</h3>
          {action.target ? <span className="mono-id">{action.target}</span> : null}
        </div>
        <ActionStateBadge state={action.state} />
      </div>
      {notice ? <Banner tone="success">{notice}</Banner> : null}
      {action.rationale ? <p>{action.rationale}</p> : null}
      <KeyValue items={[
        ['Proposed by', action.proposed_by],
        ['Proposed', <Time key="p" value={action.created_at} absolute />],
        ['Needs approval', action.requires_approval ? 'Yes' : 'No'],
        ...(action.state !== 'pending' ? [
          ['Decided by', action.decided_by] as const,
          ['Decided', <Time key="d" value={action.decided_at} absolute />] as const,
          ['Reason given', action.decision_reason] as const,
        ] : []),
      ]} />
      {params ? <JsonView value={params} label="Parameters" /> : null}

      {action.state === 'pending' ? (
        decide ? (
          <div className="row">
            <Button variant="primary" icon={Check} onClick={() => setDialog('approved')}>Approve…</Button>
            <Button variant="danger" icon={X} onClick={() => setDialog('rejected')}>Reject…</Button>
          </div>
        ) : <p className="muted">Waiting for an approver. Your role can read this proposal but not decide it.</p>
      ) : null}

      {action.state === 'approved' ? (
        detail.error && !detail.data ? <ErrorBanner error={detail.error} onRetry={detail.reload} /> :
        execution ? (
          <Banner tone="info" title="Simulated execution recorded">
            <p>Recorded by {execution.executed_by} at {formatDateTime(execution.executed_at)}. Mode: {execution.mode}. No real system was changed.</p>
          </Banner>
        ) : detail.data ? (
          decide ? (
            <div className="stack-sm">
              <div><Button icon={Play} onClick={simulate} loading={simulating}>Record simulated execution</Button></div>
              <p className="muted">Simulation only: this writes an audit record that the action would have been carried out. Nothing is executed against any system.</p>
              {simError ? <ErrorBanner error={simError} /> : null}
            </div>
          ) : <p className="muted">Approved. A simulated execution has not been recorded yet.</p>
        ) : null
      ) : null}

      {dialog ? <DecisionDialog action={action} decision={dialog} onClose={() => setDialog(null)} onDecided={onDecided} onConflict={onChanged} /> : null}
    </article>
  );
}
