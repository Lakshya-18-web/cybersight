import { useState, type FormEvent } from 'react';
import { api } from '../../api';
import { describeError, toApiError } from '../../api/errors';
import { useAuth } from '../../auth/AuthContext';
import { KeyRound } from '../../components/icons';
import { Banner } from '../../components/ui/Banner';
import { Button } from '../../components/ui/Button';
import { Card, CardBody, CardHeader } from '../../components/ui/Card';
import { PasswordField } from '../../components/ui/PasswordField';

/** Change your own password. The current one is required; your other sessions (other browsers and devices) are ended, this one stays signed in. */
export function ChangePasswordCard() {
  const { me } = useAuth();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [again, setAgain] = useState('');
  const [problems, setProblems] = useState<Record<string, string>>({});
  const [result, setResult] = useState<{ tone: 'success' | 'critical'; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const found: Record<string, string> = {};
    if (!current) found.current = 'Enter your current password.';
    if (next.length < 12) found.next = 'The new password must be at least 12 characters.';
    else if (next === current) found.next = 'Choose a password different from the current one.';
    else if (me?.username && me.username.length >= 3 && next.toLowerCase().includes(me.username)) found.next = 'The password must not contain your username.';
    if (again !== next) found.again = 'The two passwords do not match.';
    setProblems(found);
    setResult(null);
    if (Object.keys(found).length) return;
    setBusy(true);
    try {
      await api.auth.changePassword(current, next);
      setCurrent(''); setNext(''); setAgain('');
      setResult({ tone: 'success', text: 'Password changed. Your other sessions were signed out.' });
    } catch (error) {
      const e = toApiError(error);
      setResult({ tone: 'critical', text: e.kind === 'http' && e.status !== null && e.status < 500 && e.status !== 401 && e.status !== 429 ? e.message : describeError(e).detail });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardHeader title="Password" description="Change the password you sign in with." />
      <CardBody>
        <form className="stack" onSubmit={submit} noValidate>
          {result ? <Banner tone={result.tone} title={result.tone === 'success' ? undefined : 'The password was not changed'}>{result.text}</Banner> : null}
          <div className="form-grid">
            <PasswordField label="Current password" name="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" required error={problems.current} disabled={busy} />
            <PasswordField label="New password" name="new-password" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" required error={problems.next} disabled={busy}
              hint="At least 12 characters." />
            <PasswordField label="Repeat new password" name="repeat-password" value={again} onChange={(e) => setAgain(e.target.value)} autoComplete="new-password" required error={problems.again} disabled={busy} />
          </div>
          <div><Button type="submit" icon={KeyRound} loading={busy}>Change password</Button></div>
        </form>
      </CardBody>
    </Card>
  );
}
