import { useEffect, useRef, useState, type FormEvent } from 'react';
import { api } from '../api';
import { toApiError } from '../api/errors';
import { usePermissions } from '../auth/AuthContext';
import { Banner, ErrorBanner } from '../components/ui/Banner';
import { Button } from '../components/ui/Button';
import { Card, CardBody, CardHeader } from '../components/ui/Card';
import { SelectField, TextAreaField, TextField } from '../components/ui/Field';
import { JsonView } from '../components/ui/JsonView';
import { PageHeader } from '../components/ui/PageHeader';
import { ArrowLeft, Send } from '../components/icons';
import { Icon } from '../components/ui/Icon';
import { JobSummary } from '../features/jobs/JobPanels';
import { useJob } from '../features/jobs/useJob';
import { JobStatusBadge } from '../components/ui/Badge';
import { ALERT_FIELDS, FIELD_GROUPS, emptyValues, parseImportedJson, toAlert, validateAll, validateField, type FormValues, EXAMPLE_ALERT } from '../lib/alertSchema';
import { Link } from '../lib/router';

interface Accepted { jobId: string; duplicate: boolean }

function JobFollower({ jobId }: { jobId: string }) {
  const job = useJob(jobId);
  return (
    <div className="stack">
      {job.error && !job.data ? <ErrorBanner error={job.error} onRetry={job.refresh} /> : null}
      {job.data ? <JobSummary job={job.data} /> : <p className="muted" role="status">Waiting for the first status…</p>}
      <div className="row" role="status" aria-live="polite">
        {job.data ? <JobStatusBadge status={job.data.status} /> : null}
        {job.polling ? <span className="muted">Checking every few seconds; this stops when the job finishes.</span> : null}
        {job.stopReason === 'timeout' ? <><span className="muted">Stopped checking after 10 minutes.</span><Button size="sm" onClick={job.refresh}>Check again</Button></> : null}
        {job.stopReason === 'errors' ? <><span className="muted">Stopped after repeated errors.</span><Button size="sm" onClick={job.refresh}>Check again</Button></> : null}
        {job.data?.case_id ? <Link to={`/cases/${job.data.case_id}`} className="btn" data-variant="primary">Open the case</Link> : null}
        <Link to={`/jobs/${jobId}`}>Job page</Link>
      </div>
    </div>
  );
}

export function SubmitAlertPage() {
  const { submit } = usePermissions();
  const [mode, setMode] = useState<'form' | 'json'>('form');
  const [values, setValues] = useState<FormValues>(emptyValues);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [touched, setTouched] = useState<Record<string, boolean>>({});
  const [memory, setMemory] = useState<'off' | 'on'>('off');
  const [json, setJson] = useState('');
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<unknown>(null);
  const [accepted, setAccepted] = useState<Accepted | null>(null);
  const [retryIn, setRetryIn] = useState(0);
  const summaryRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (retryIn <= 0) return;
    const t = setTimeout(() => setRetryIn((n) => n - 1), 1000);
    return () => clearTimeout(t);
  }, [retryIn]);

  if (!submit) {
    return (
      <>
        <PageHeader title="Submit alert" />
        <Banner tone="warning" title="Your role cannot submit alerts">Viewers can read alerts and jobs. Ask an administrator for an analyst role to submit.</Banner>
      </>
    );
  }

  const setField = (name: string, value: string) => {
    setValues((v) => ({ ...v, [name]: value }));
    setFailure(null);
    if (touched[name] || errors[name]) {
      const def = ALERT_FIELDS.find((f) => f.name === name);
      const message = def ? validateField(def, value) : null;
      setErrors((e) => { const next = { ...e }; if (message) next[name] = message; else delete next[name]; return next; });
    }
  };

  const onBlur = (name: string) => {
    setTouched((t) => ({ ...t, [name]: true }));
    const def = ALERT_FIELDS.find((f) => f.name === name);
    const message = def ? validateField(def, values[name] ?? '') : null;
    setErrors((e) => { const next = { ...e }; if (message) next[name] = message; else delete next[name]; return next; });
  };

  const applyJson = () => {
    const result = parseImportedJson(json);
    if (!result.ok) { setJsonError(result.error); return; }
    setJsonError(null);
    setValues(result.values);
    if (result.memory) setMemory(result.memory);
    setErrors({});
    setTouched({});
    setMode('form');
  };

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (busy || retryIn > 0) return;
    const found = validateAll(values);
    setTouched(Object.fromEntries(ALERT_FIELDS.map((f) => [f.name, true])));
    setErrors(found);
    setFailure(null);
    const firstBad = ALERT_FIELDS.findIndex((f) => found[f.name]);
    if (firstBad !== -1) {
      summaryRef.current?.focus();
      return;
    }
    // No Idempotency-Key is sent: the server recognises an identical alert by its content, so a retry or a double click returns the existing job instead of queuing a second one.
    const body = { alert: toAlert(values), memory };
    setBusy(true);
    try {
      const res = await api.submitAlert(body);
      setAccepted({ jobId: res.job_id, duplicate: res.duplicate });
    } catch (e) {
      const err = toApiError(e);
      if (err.status === 422 && err.field && ALERT_FIELDS.some((f) => f.name === err.field)) {
        setErrors((prev) => ({ ...prev, [err.field as string]: `The server rejected this value: ${err.message}` }));
      }
      if (err.isRateLimited && err.retryAfterSeconds) setRetryIn(err.retryAfterSeconds);
      setFailure(err);
    } finally {
      setBusy(false);
    }
  };

  const startOver = () => {
    setAccepted(null);
    setValues(emptyValues());
    setErrors({});
    setTouched({});
    setFailure(null);
  };

  if (accepted) {
    return (
      <>
        <PageHeader title="Alert submitted" description="The alert is queued; a worker triages it and creates a case."
          actions={<Button icon={Send} onClick={startOver}>Submit another</Button>} />
        {accepted.duplicate ? <Banner tone="info" title="This alert was already submitted">The API recognised it and returned the existing job instead of creating a new one.</Banner> : <Banner tone="success" title="Accepted">Job {accepted.jobId.slice(0, 8)} is queued.</Banner>}
        <JobFollower jobId={accepted.jobId} />
      </>
    );
  }

  const errorCount = Object.keys(errors).length;
  const err = failure ? toApiError(failure) : null;
  const preview = errorCount === 0 && ALERT_FIELDS.every((f) => (values[f.name] ?? '').trim() !== '') ? { alert: toAlert(values), memory } : null;

  return (
    <>
      <PageHeader crumbs={[{ label: 'Alerts', to: '/alerts' }, { label: 'Submit alert' }]} title="Submit alert" description="Send one alert to the triage agent. The form has exactly the 21 fields the API accepts; nothing else can be sent."
        actions={<Link to="/alerts" className="btn" data-variant="ghost"><Icon icon={ArrowLeft} size={16} />Alerts</Link>} />
      <div className="segmented" role="group" aria-label="Input method">
        <button type="button" aria-pressed={mode === 'form'} onClick={() => setMode('form')}>Form</button>
        <button type="button" aria-pressed={mode === 'json'} onClick={() => setMode('json')}>Paste JSON</button>
      </div>

      {mode === 'json' ? (
        <Card>
          <CardHeader title="Paste JSON" description='Either the whole request body {"alert": {…}, "memory": "off"} or just the alert object. It fills the form so you can check it before sending.' />
          <CardBody>
            <div className="stack">
              <TextAreaField label="Alert JSON" value={json} onChange={(e) => { setJson(e.target.value); setJsonError(null); }} rows={12} data-mono="true" spellCheck={false} error={jsonError ?? undefined} />
              <div className="row"><Button variant="primary" onClick={applyJson} disabled={json.trim() === ''}>Fill the form</Button><Button onClick={() => { setJson(JSON.stringify({ alert: EXAMPLE_ALERT, memory: 'off' }, null, 2)); setJsonError(null); }}>Insert example</Button></div>
              <p className="section-note">The example is invented (reserved documentation addresses, made-up numbers). It is checked by the same rules as anything you type, and nothing is sent until you submit the form.</p>
            </div>
          </CardBody>
        </Card>
      ) : (
        <form className="stack" onSubmit={onSubmit} noValidate aria-label="Alert">
          <div ref={summaryRef} tabIndex={-1}>
            {errorCount > 0 && Object.keys(touched).length > 0 ? (
              <Banner tone="critical" title={`${errorCount} field${errorCount === 1 ? ' needs' : 's need'} attention`}>
                <ul className="bullets">{ALERT_FIELDS.filter((f) => errors[f.name]).map((f) => <li key={f.name}>{f.label}: {errors[f.name]}</li>)}</ul>
              </Banner>
            ) : null}
          </div>
          {FIELD_GROUPS.map((group) => (
            <fieldset className="fieldset" key={group.id}>
              <legend>{group.title}</legend>
              <p className="muted">{group.description}</p>
              <div className="form-grid">
                {ALERT_FIELDS.filter((f) => f.group === group.id).map((f) => (
                  <TextField key={f.name} label={f.label} value={values[f.name] ?? ''} onChange={(e) => setField(f.name, e.target.value)} onBlur={() => onBlur(f.name)}
                    error={errors[f.name]} hint={f.hint} required placeholder={f.placeholder} autoComplete="off" spellCheck={false}
                    inputMode={f.kind === 'port' || f.kind === 'protocol' ? 'numeric' : f.kind === 'score' || f.kind === 'number' ? 'decimal' : 'text'} />
                ))}
              </div>
            </fieldset>
          ))}
          <fieldset className="fieldset">
            <legend>Options</legend>
            <SelectField label="Memory" value={memory} onChange={(e) => { setMemory(e.target.value as 'off' | 'on'); setFailure(null); }}
              hint="Memory lets the agent compare with similar past cases. It can only make the routing more cautious. If the server has no memory configured it will say so.">
              <option value="off">Off</option>
              <option value="on">On</option>
            </SelectField>
          </fieldset>
          {err ? (
            err.isUnreachable ? <Banner tone="warning" title="No answer from the API">The alert may or may not have arrived. Sending again is safe: an identical alert is recognised by the server and is not queued twice.</Banner>
            : err.isRateLimited ? <Banner tone="warning" title="Slow down">{err.message}. {retryIn > 0 ? `You can send again in ${retryIn} s.` : 'You can send again now.'}</Banner>
            : <ErrorBanner error={err} />
          ) : null}
          <div className="row">
            <Button type="submit" variant="primary" icon={Send} loading={busy} disabled={retryIn > 0}>Submit alert</Button>
            <Button onClick={startOver} disabled={busy}>Clear form</Button>
          </div>
          {preview ? <JsonView value={preview} label="Request that will be sent" /> : null}
        </form>
      )}
    </>
  );
}
