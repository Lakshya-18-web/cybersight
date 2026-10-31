import { useState, type FormEvent } from 'react';
import { api } from '../../api';
import { Button } from '../../components/ui/Button';
import { Card, CardBody } from '../../components/ui/Card';
import { SelectField, TextField } from '../../components/ui/Field';
import { useResource } from '../../hooks/useResource';
import { UUID_RE } from '../../lib/ids';

/** Choose one case: from the 50 newest (GET /cases) or by pasting its id. The API has no feed across all cases for the pages that use this, so the choice is always explicit. */
export function CasePicker({ caseId, onPick, submitLabel }: { caseId: string; onPick: (id: string) => void; submitLabel: string }) {
  const [typed, setTyped] = useState(caseId);
  const [problem, setProblem] = useState<string | null>(null);
  const recent = useResource((signal) => api.listCases({ limit: 50 }, { signal }), []);
  const open = (value: string) => {
    const v = value.trim();
    if (v === '') { setProblem(null); onPick(''); return; }
    if (!UUID_RE.test(v)) { setProblem('A case id looks like 3f2b8c1e-5a7d-4e0b-9c4a-1d2e3f4a5b6c.'); return; }
    setProblem(null); setTyped(v); onPick(v.toLowerCase());
  };
  const onSubmit = (e: FormEvent) => { e.preventDefault(); open(typed); };
  return (
    <Card>
      <CardBody>
        <form className="filters" onSubmit={onSubmit} noValidate>
          <SelectField label="Recent cases" value={recent.data?.items.some((c) => c.case_id === caseId) ? caseId : ''} onChange={(e) => open(e.target.value)} disabled={!recent.data}
            hint={recent.error ? 'The case list could not be loaded; paste an id instead.' : recent.data ? 'The 50 most recent.' : 'Loading…'}>
            <option value="">Choose a case…</option>
            {recent.data?.items.map((c) => <option key={c.case_id} value={c.case_id}>{c.alert_id} · {c.case_id.slice(0, 8)}</option>)}
          </SelectField>
          <TextField label="Or paste a case id" value={typed} onChange={(e) => { setTyped(e.target.value); setProblem(null); }} error={problem ?? undefined} spellCheck={false} autoComplete="off" />
          <Button type="submit" variant="primary">{submitLabel}</Button>
        </form>
      </CardBody>
    </Card>
  );
}
