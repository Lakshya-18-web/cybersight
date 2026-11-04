import { useEffect, useState, type FormEvent } from 'react';
import { api } from '../api';
import { toApiError } from '../api/errors';
import { signInMessage } from '../auth/messages';
import { Logo } from '../components/brand/Logo';
import { KeyRound } from '../components/icons';
import { Banner } from '../components/ui/Banner';
import { Button } from '../components/ui/Button';
import { Card, CardBody } from '../components/ui/Card';
import { TextField } from '../components/ui/Field';
import { PasswordField } from '../components/ui/PasswordField';
import { LoadingRows } from '../components/ui/State';
import { Link, useNavigate } from '../lib/router';

export const PASSWORD_HELP = 'At least 12 characters. A few ordinary words make a good password. It must not contain the username.';
const USERNAME_RE = /^[a-z0-9][a-z0-9_.-]{2,31}$/;

/** One-time creation of the first administrator. It only works while the server's setup secret (WEEK5_BOOTSTRAP_TOKEN) is set and no administrator exists; the password is typed here and sent
 *  once to the API over HTTPS. It is never stored, logged or kept in this page after the request. */
export function SetupPage({ onDone }: { onDone: () => void }) {
  const navigate = useNavigate();
  const [open, setOpen] = useState<boolean | null>(null);
  const [secret, setSecret] = useState('');
  const [username, setUsername] = useState('lakshya');
  const [display, setDisplay] = useState('');
  const [password, setPassword] = useState('');
  const [again, setAgain] = useState('');
  const [problems, setProblems] = useState<Record<string, string>>({});
  const [failure, setFailure] = useState<ReturnType<typeof signInMessage> | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    api.auth.status({ signal: controller.signal }).then((s) => setOpen(s.bootstrap_available), () => setOpen(false));
    return () => controller.abort();
  }, []);

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    const next: Record<string, string> = {};
    const name = username.trim().toLowerCase();
    if (!secret.trim()) next.secret = 'Enter the setup secret.';
    if (!USERNAME_RE.test(name)) next.username = 'Use 3 to 32 characters: lower-case letters, digits, dot, underscore or hyphen.';
    if (password.length < 12) next.password = 'The password must be at least 12 characters.';
    else if (password.toLowerCase().includes(name) && name.length >= 3) next.password = 'The password must not contain the username.';
    if (again !== password) next.again = 'The two passwords do not match.';
    setProblems(next);
    setFailure(null);
    if (Object.keys(next).length) return;
    setBusy(true);
    try {
      await api.auth.bootstrap({ bootstrap_secret: secret.trim(), username: name, password, ...(display.trim() ? { display_name: display.trim() } : {}) });
      setSecret(''); setPassword(''); setAgain('');
      onDone();
      navigate('/', { replace: true });
    } catch (error) {
      setFailure(signInMessage(toApiError(error), true));
      setBusy(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-top"><div className="brand"><Logo size={40} /></div></div>
      <div className="auth-card stack">
        <Card>
          <CardBody>
            {open === null ? <LoadingRows rows={3} label="Checking setup" /> : !open ? (
              <div className="stack">
                <h1>First-time setup</h1>
                <Banner tone="info" title="Setup is not open">Either the administrator account already exists, or the API was not started with a setup secret. If you are an administrator, sign in instead.</Banner>
                <Link to="/">Go to sign in</Link>
              </div>
            ) : (
              <form className="stack" onSubmit={onSubmit} noValidate>
                <div>
                  <h1>Create the administrator</h1>
                  <p className="muted">This page works once. It needs the setup secret from the API service's environment (WEEK5_BOOTSTRAP_TOKEN). After it succeeds, remove that variable from the service.</p>
                </div>
                {failure ? <Banner tone="critical" title={failure.title}>{failure.detail}</Banner> : null}
                <PasswordField label="Setup secret" name="bootstrap-secret" value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="off" required error={problems.secret} disabled={busy} />
                <TextField label="Username" name="username" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoCapitalize="none" spellCheck={false}
                  required error={problems.username} disabled={busy} />
                <TextField label="Display name" name="display-name" value={display} onChange={(e) => setDisplay(e.target.value)} autoComplete="name" maxLength={100} disabled={busy} hint="Optional. Shown in the top bar." />
                <PasswordField label="Password" name="new-password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" required error={problems.password}
                  hint={PASSWORD_HELP} disabled={busy} />
                <PasswordField label="Repeat password" name="repeat-password" value={again} onChange={(e) => setAgain(e.target.value)} autoComplete="new-password" required error={problems.again} disabled={busy} />
                <Button type="submit" variant="primary" icon={KeyRound} loading={busy}>Create administrator</Button>
                <Link to="/">Back to sign in</Link>
              </form>
            )}
          </CardBody>
        </Card>
      </div>
    </div>
  );
}
