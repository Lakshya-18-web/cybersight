import { useState, type FormEvent } from 'react';
import { useAuth } from '../auth/AuthContext';
import { toApiError } from '../api/errors';
import { HealthIndicator } from '../components/layout/HealthIndicator';
import { Banner, ErrorBanner } from '../components/ui/Banner';
import { Button } from '../components/ui/Button';
import { Card, CardBody } from '../components/ui/Card';
import { TextField } from '../components/ui/Field';
import { KeyRound } from '../components/icons';
import { Logo } from '../components/brand/Logo';
import { config } from '../config';

export function SignInPage() {
  const { signIn, notice } = useAuth();
  const [mode, setMode] = useState<'token' | 'dev'>('token');
  const [token, setToken] = useState('');
  const [analyst, setAnalyst] = useState('');
  const [remember, setRemember] = useState(false);
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    const value = (mode === 'token' ? token : analyst).trim();
    if (!value) { setError(new Error('empty')); return; }
    setBusy(true);
    setError(null);
    try {
      await signIn(mode === 'token' ? { kind: 'bearer', token: value } : { kind: 'dev', analyst: value }, remember);
    } catch (e) {
      setError(toApiError(e));
      setBusy(false);
    }
  };

  const err = error ? toApiError(error) : null;
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
                <p className="muted">Use the API token your administrator issued to you.</p>
              </div>
              {notice ? <Banner tone="warning">{notice}</Banner> : null}
              {err && err.message === 'empty' ? <Banner tone="critical" title="Enter a credential to continue." /> : null}
              {err && err.message !== 'empty' ? (
                err.status === 401 ? <Banner tone="critical" title="That token was not accepted">Check that you pasted the whole token. Tokens are shown once when they are created.</Banner>
                : err.status === 403 ? <Banner tone="critical" title="This account cannot sign in">The account is not active or is not registered with the API.</Banner>
                : <ErrorBanner error={err} />
              ) : null}
              {config.devSignIn ? (
                <div className="segmented" role="group" aria-label="Sign-in method">
                  <button type="button" aria-pressed={mode === 'token'} onClick={() => setMode('token')}>API token</button>
                  <button type="button" aria-pressed={mode === 'dev'} onClick={() => setMode('dev')}>Dev analyst</button>
                </div>
              ) : null}
              {mode === 'token' ? (
                <>
                  <TextField label="API token" type={show ? 'text' : 'password'} value={token} onChange={(e) => setToken(e.target.value)} autoComplete="off" spellCheck={false} autoFocus required
                    hint="Kept in this tab's memory. It is never written to the page or sent anywhere except the API." />
                  <label className="checkbox"><input type="checkbox" checked={show} onChange={(e) => setShow(e.target.checked)} /> Show token</label>
                  <label className="checkbox"><input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} />
                    <span>Keep me signed in for this browser tab<br /><span className="muted">Stores the token in this tab's session storage until the tab closes. Leave off on a shared computer.</span></span>
                  </label>
                </>
              ) : (
                <TextField label="Analyst id" value={analyst} onChange={(e) => setAnalyst(e.target.value)} autoComplete="off" required
                  hint="Development servers only (WEEK4_API_DEV_MODE=1). The API refuses this when token authentication is configured." />
              )}
              <Button type="submit" variant="primary" icon={KeyRound} loading={busy}>Sign in</Button>
            </form>
          </CardBody>
        </Card>
        <div className="row-between"><span className="muted">API status</span><HealthIndicator /></div>
      </div>
    </div>
  );
}
