import { useRef, useState } from 'react';
import { api } from '../../api';
import { toApiError } from '../../api/errors';
import type { DecisionResult, ProposedAction } from '../../api/types';
import { Banner, ErrorBanner } from '../../components/ui/Banner';
import { Button } from '../../components/ui/Button';
import { Dialog } from '../../components/ui/Dialog';
import { TextAreaField } from '../../components/ui/Field';
import { KeyValue } from '../../components/ui/KeyValue';
import { humanize } from '../../lib/format';
import { newIdempotencyKey } from '../../lib/ids';

export const REASON_MAX = 1000;

interface Props {
  action: Pick<ProposedAction, 'action_id' | 'action_type' | 'target' | 'rationale'>;
  decision: 'approved' | 'rejected';
  onClose: () => void;
  /** Called after the API recorded the decision (or reported it was already recorded), with its answer. */
  onDecided: (result: DecisionResult) => void;
  /** Called when the API says the action changed under us (409), so the page can reload it. */
  onConflict: () => void;
}

/** Approve or reject one proposed action. A reason is required (1-1000 characters) and goes into the audit trail.
 *  The Idempotency-Key is made once per opened dialog and reused on every retry, so a retry after a dropped connection cannot decide twice. */
export function DecisionDialog({ action, decision, onClose, onDecided, onConflict }: Props) {
  const key = useRef(newIdempotencyKey('decision'));
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [touched, setTouched] = useState(false);

  const trimmed = reason.trim();
  const problem = trimmed.length === 0 ? 'A reason is required; it is kept in the audit trail.' : trimmed.length > REASON_MAX ? `Keep the reason to ${REASON_MAX} characters or fewer.` : undefined;
  const approve = decision === 'approved';

  const submit = async () => {
    setTouched(true);
    if (problem) return;
    setBusy(true);
    setError(null);
    try {
      const result = await api.decide(action.action_id, decision, trimmed, key.current);
      onDecided(result);
    } catch (e) {
      const err = toApiError(e);
      if (err.isConflict) onConflict();
      setError(err);
      setBusy(false);
    }
  };

  const err = error ? toApiError(error) : null;
  return (
    <Dialog
      title={approve ? 'Approve this action' : 'Reject this action'}
      onClose={onClose}
      busy={busy}
      footer={<>
        <Button onClick={onClose} disabled={busy}>Cancel</Button>
        <Button variant={approve ? 'primary' : 'danger'} loading={busy} onClick={submit}>{approve ? 'Approve' : 'Reject'}</Button>
      </>}
    >
      <Banner tone="info">Approving records your decision. Nothing is executed against any system; a simulated execution can be recorded afterwards.</Banner>
      <KeyValue items={[['Action', humanize(action.action_type)], ['Target', action.target], ['Proposed because', action.rationale]]} />
      <TextAreaField label="Reason" required value={reason} onChange={(e) => setReason(e.target.value)} onBlur={() => setTouched(true)} rows={4} maxLength={REASON_MAX + 200}
        error={touched ? problem : undefined} hint={`${trimmed.length} / ${REASON_MAX}`} data-autofocus="" />
      {err ? (err.isConflict ? <Banner tone="warning" title="This action was already decided">{err.message}. The page has been refreshed with the current state.</Banner> : <ErrorBanner error={err} />) : null}
    </Dialog>
  );
}
