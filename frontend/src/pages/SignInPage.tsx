import { useEffect, useState, type FormEvent } from 'react';
import { api } from '../api';
import { toApiError } from '../api/errors';
import { signInMessage } from '../auth/messages';
import { useAuth } from '../auth/AuthContext';
import { Logo } from '../components/brand/Logo';
import { HealthIndicator } from '../components/layout/HealthIndicator';
import { KeyRound } from '../components/icons';
import { Banner } from '../components/ui/Banner';
import { Button } from '../components/ui/Button';
import { Card, CardBody } from '../components/ui/Card';
import { TextField } from '../components/ui/Field';
import { PasswordField } from '../components/ui/PasswordField';
import { Link } from '../lib/router';

/** Username and password only. There is no API token, no analyst id and no "remember me" here: the server decides how long a session lasts and keeps it in an HttpOnly cookie. */
export function SignInPage({ justCreated = false }: { justCreated?: boolean }) {
  const { signIn, status, notice } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [problems, setProblems] = useState<{ username?: string; password?: string }>({});
  const [failure, setFailure] = useState<ReturnType<typeof signInMessage> | null>(null);
  const [setupOpen, setSetupOpen] = useState(false);
  const busy = status === 'signingIn';

  // Offer first-time setup only while the server says it is open. A failure to ask is not an error worth showing here.
  useEffect(() => {
    const controller = new AbortController();
    api.auth.status({ signal: controller.signal }).then((s) => setSetupOpen(s.bootstrap_available), () => undefined);
    return () => controller.abort();
  }, []);

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    const next: typeof problems = {};
    if (!username.trim()) next.username = 'Enter your username.';
    if (!password) next.password = 'Enter your password.';
    setProblems(next);
    setFailure(null);
    if (next.username || next.password) return;
    try {
      await signIn(username.trim(), password);
    } catch (error) {
      setFailure(signInMessage(toApiError(error)));
      setPassword('');
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-top">
        <div className="brand"><Logo size={40} /></div>
      </div>
      <div className="auth-card stack">
        <Card>
          <CardBody>
            <form className="stack" onSubmit={onSubmit} noValidate>
              <div>
                <h1>Sign in to CyberSight</h1>
                <p className="tagline">See threats sooner. Respond smarter.</p>
              </div>
              {justCreated ? <Banner tone="success" title="Administrator account created">Sign in with the username and password you just chose.</Banner> : null}
              {notice ? <Banner tone="warning">{notice}</Banner> : null}
              {failure ? <Banner tone="critical" title={failure.title}>{failure.detail}</Banner> : null}
              <TextField label="Username" name="username" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoCapitalize="none" spellCheck={false}
                autoFocus required error={problems.username} disabled={busy} />
              <PasswordField label="Password" name="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required
                error={problems.password} disabled={busy} />
              <Button type="submit" variant="primary" icon={KeyRound} loading={busy}>{busy ? 'Signing in…' : 'Sign in'}</Button>
              <p className="muted">Accounts are created by an administrator. Forgotten your password? Ask an administrator to reset it.</p>
              {setupOpen ? <div className="auth-links"><Link to="/setup">First-time setup: create the administrator account</Link></div> : null}
            </form>
          </CardBody>
        </Card>
        <div className="row-between"><span className="muted">API status</span><HealthIndicator /></div>
      </div>
    </div>
  );
}
