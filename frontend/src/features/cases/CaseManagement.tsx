import { useRef, useState } from 'react';
import { api } from '../../api';
import { toApiError } from '../../api/errors';
import { ASSESSMENTS, DISPOSITIONS, type Assessment, type CaseAnalysis, type Disposition } from '../../api/types';
import { usePermissions } from '../../auth/AuthContext';
import { Check } from '../../components/icons';
import { Badge } from '../../components/ui/Badge';
import { Banner, ErrorBanner } from '../../components/ui/Banner';
import { Button } from '../../components/ui/Button';
import { Card, CardBody, CardHeader } from '../../components/ui/Card';
import { Dialog } from '../../components/ui/Dialog';
import { SelectField, TextAreaField } from '../../components/ui/Field';
import { Time } from '../../components/ui/Time';
import { canResolve, COMMENT_MAX, NOTE_MAX, REASON_MAX, validateText } from '../../lib/caseForms';
import { humanize } from '../../lib/format';
import { newIdempotencyKey } from '../../lib/ids';

/** Runs one write with a key that is made once per attempt and reused by every retry of that same attempt, so a dropped connection followed by a second click cannot add the item twice.
 *  After a success the key is replaced, so the next submission is a new one. */
function useWrite<T>(prefix: string, run: (key: string) => Promise<T>, onDone: (result: T) => void) {
  const key = useRef(newIdempotencyKey(prefix));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const go = async () => {
    setBusy(true);
    setError(null);
    try {
      const result = await run(key.current);
      key.current = newIdempotencyKey(prefix);
      onDone(result);
    } catch (e) {
      setError(toApiError(e));
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, go };
}

const NOT_SENT = 'Notes, feedback and resolutions are kept for people and for evaluation. They are never given to a model and never change the verdict or the routing.';

function NoteForm({ caseId, onSaved }: { caseId: string; onSaved: () => void }) {
  const [text, setText] = useState('');
  const [touched, setTouched] = useState(false);
  const [saved, setSaved] = useState(false);
  const problem = validateText(text, NOTE_MAX, true, 'A note');
  const w = useWrite('note', (k) => api.addNote(caseId, text.trim(), k), () => { setText(''); setTouched(false); setSaved(true); onSaved(); });
  return (
    <form className="stack-sm" onSubmit={(e) => { e.preventDefault(); setTouched(true); setSaved(false); if (!problem) void w.go(); }} aria-label="New note">
      <TextAreaField label="Add a note" value={text} onChange={(e) => { setText(e.target.value); setSaved(false); }} rows={3} error={touched ? problem : undefined} hint={`${text.trim().length} / ${NOTE_MAX}`} />
      {w.error ? <ErrorBanner error={w.error} /> : null}
      {saved ? <Banner tone="success">Note added.</Banner> : null}
      <div><Button type="submit" variant="primary" loading={w.busy}>Add note</Button></div>
    </form>
  );
}

function FeedbackForm({ caseId, onSaved }: { caseId: string; onSaved: () => void }) {
  const [assessment, setAssessment] = useState<Assessment | ''>('');
  const [disposition, setDisposition] = useState<Disposition | ''>('');
  const [comment, setComment] = useState('');
  const [touched, setTouched] = useState(false);
  const [saved, setSaved] = useState(false);
  const commentProblem = validateText(comment, COMMENT_MAX, false, 'The comment');
  const problem = assessment === '' ? 'Say whether the verdict was correct.' : undefined;
  const w = useWrite('feedback', (k) => api.addFeedback(caseId, { assessment: assessment as Assessment, ...(disposition ? { disposition } : {}), ...(comment.trim() ? { comment: comment.trim() } : {}) }, k),
    () => { setAssessment(''); setDisposition(''); setComment(''); setTouched(false); setSaved(true); onSaved(); });
  return (
    <form className="stack-sm" onSubmit={(e) => { e.preventDefault(); setTouched(true); setSaved(false); if (!problem && !commentProblem) void w.go(); }} aria-label="Verdict feedback">
      <div className="filters">
        <SelectField label="Was the verdict correct?" value={assessment} onChange={(e) => setAssessment(e.target.value as Assessment | '')} error={touched ? problem : undefined}>
          <option value="">Choose…</option>
          {ASSESSMENTS.map((a) => <option key={a} value={a}>{humanize(a)}</option>)}
        </SelectField>
        <SelectField label="What was it really?" value={disposition} onChange={(e) => setDisposition(e.target.value as Disposition | '')}>
          <option value="">Not stated</option>
          {DISPOSITIONS.map((d) => <option key={d} value={d}>{humanize(d)}</option>)}
        </SelectField>
      </div>
      <TextAreaField label="Comment (optional)" value={comment} onChange={(e) => setComment(e.target.value)} rows={2} error={touched ? commentProblem : undefined} hint={`${comment.trim().length} / ${COMMENT_MAX}`} />
      {w.error ? <ErrorBanner error={w.error} /> : null}
      {saved ? <Banner tone="success">Feedback recorded.</Banner> : null}
      <div><Button type="submit" variant="primary" loading={w.busy}>Record feedback</Button></div>
    </form>
  );
}

function ResolveDialog({ caseId, onClose, onResolved }: { caseId: string; onClose: () => void; onResolved: () => void }) {
  const [reason, setReason] = useState('');
  const [disposition, setDisposition] = useState<Disposition | ''>('');
  const [touched, setTouched] = useState(false);
  const problem = validateText(reason, REASON_MAX, true, 'A reason');
  const w = useWrite('resolve', (k) => api.resolveCase(caseId, reason.trim(), disposition || undefined, k), () => onResolved());
  const err = w.error ? toApiError(w.error) : null;
  return (
    <Dialog title="Resolve this case" onClose={onClose} busy={w.busy}
      footer={<><Button onClick={onClose} disabled={w.busy}>Cancel</Button><Button variant="primary" icon={Check} loading={w.busy} onClick={() => { setTouched(true); if (!problem) void w.go(); }}>Resolve</Button></>}>
      <Banner tone="info">Resolving records your decision that no further work is needed. It approves, rejects and executes nothing, and it does not change the verdict.</Banner>
      <TextAreaField label="Reason" required value={reason} onChange={(e) => setReason(e.target.value)} rows={4} error={touched ? problem : undefined} hint={`${reason.trim().length} / ${REASON_MAX}`} data-autofocus="" />
      <SelectField label="What was it really? (optional)" value={disposition} onChange={(e) => setDisposition(e.target.value as Disposition | '')}>
        <option value="">Not stated</option>
        {DISPOSITIONS.map((d) => <option key={d} value={d}>{humanize(d)}</option>)}
      </SelectField>
      {err ? (err.code === 'pending_actions' ? <Banner tone="warning" title="Proposed actions are still waiting">Decide them first, then resolve the case.</Banner>
        : err.isConflict ? <Banner tone="warning" title="The case changed">It may already be resolved. Close this window and refresh.</Banner> : <ErrorBanner error={err} />) : null}
    </Dialog>
  );
}

/** Notes, feedback, resolution and the history of both. Controls appear only when the signed-in role may use them (the API enforces it either way). */
export function CaseManagement({ analysis, onChanged }: { analysis: CaseAnalysis; onChanged: () => void }) {
  const { submit } = usePermissions();
  const [resolving, setResolving] = useState(false);
  const caseId = analysis.case.case_id;
  const pending = analysis.evidence_classes.policy_decision.actions.filter((a) => a.state === 'pending').length;
  const check = canResolve(analysis.case.status, pending);
  return (
    <div className="stack">
      <Banner tone="info" title="Kept for people, never for the model">{NOT_SENT}</Banner>
      <div className="grid grid-2">
        <Card>
          <CardHeader title="Notes" description={`${analysis.notes.length} on this case`} />
          <CardBody>
            <div className="stack">
              {analysis.notes.length === 0 ? <p className="muted">No notes yet.</p> : (
                <ul role="list">
                  {analysis.notes.map((n) => (
                    <li key={n.note_id} className="note-item">
                      <div className="row"><strong>{n.author}</strong>{n.kind !== 'note' ? <Badge tone="accent">{humanize(n.kind)}</Badge> : null}<span className="muted"><Time value={n.created_at} absolute /></span></div>
                      <p>{n.body}</p>
                    </li>
                  ))}
                </ul>
              )}
              {submit ? <NoteForm caseId={caseId} onSaved={onChanged} /> : <p className="muted">Your role can read notes but not add them.</p>}
            </div>
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Feedback on the verdict" description={`${analysis.feedback.length} recorded`} />
          <CardBody>
            <div className="stack">
              {analysis.feedback.length === 0 ? <p className="muted">No feedback yet.</p> : (
                <ul role="list">
                  {analysis.feedback.map((f) => (
                    <li key={f.feedback_id} className="note-item">
                      <div className="row"><strong>{f.author}</strong><Badge tone={f.verdict_assessment === 'correct' ? 'success' : f.verdict_assessment === 'incorrect' ? 'critical' : 'neutral'}>{humanize(f.verdict_assessment)}</Badge>
                        {f.disposition ? <Badge>{humanize(f.disposition)}</Badge> : null}<span className="muted"><Time value={f.created_at} absolute /></span></div>
                      {f.comment ? <p>{f.comment}</p> : null}
                    </li>
                  ))}
                </ul>
              )}
              {submit ? <FeedbackForm caseId={caseId} onSaved={onChanged} /> : <p className="muted">Your role can read feedback but not add it.</p>}
            </div>
          </CardBody>
        </Card>
      </div>
      <Card>
        <CardHeader title="Resolve" description="Close an escalated or needs-review case by hand." />
        <CardBody>
          {!submit ? <p className="muted">Your role cannot resolve cases.</p>
            : check.allowed ? <Button variant="primary" icon={Check} onClick={() => setResolving(true)}>Resolve this case…</Button>
            : <p className="muted">{check.why}</p>}
        </CardBody>
      </Card>
      {resolving ? <ResolveDialog caseId={caseId} onClose={() => setResolving(false)} onResolved={() => { setResolving(false); onChanged(); }} /> : null}
    </div>
  );
}
