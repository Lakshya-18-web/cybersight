import { useState, type FormEvent } from 'react';
import { api } from '../api';
import { describeError, toApiError } from '../api/errors';
import { ROLES, type AccountRow, type Role } from '../api/types';
import { useAuth } from '../auth/AuthContext';
import { Briefcase, KeyRound, LogOut, RefreshCw, ShieldCheck, X } from '../components/icons';
import { Badge } from '../components/ui/Badge';
import { Banner, ErrorBanner } from '../components/ui/Banner';
import { Button } from '../components/ui/Button';
import { Card, CardBody, CardHeader } from '../components/ui/Card';
import { Dialog } from '../components/ui/Dialog';
import { SelectField, TextField } from '../components/ui/Field';
import { PageHeader } from '../components/ui/PageHeader';
import { PasswordField } from '../components/ui/PasswordField';
import { EmptyState, ErrorState, LoadingRows } from '../components/ui/State';
import { Time } from '../components/ui/Time';
import { useResource } from '../hooks/useResource';
import { PASSWORD_HELP } from './SetupPage';

const USERNAME_RE = /^[a-z0-9][a-z0-9_.-]{2,31}$/;
const ROLE_HELP: Record<Role, string> = {
  viewer: 'Can read dashboards, cases and jobs.',
  analyst: 'Viewer, and can submit alerts and add notes and feedback.',
  approver: 'Analyst, and can approve or reject proposed actions.',
  admin: 'Approver, and can manage accounts.',
};

type Dialogs = { kind: 'create' } | { kind: 'reset'; row: AccountRow } | null;

/** Administrators only (the API enforces it; this page is also hidden from everyone else). Accounts are created here; there is no public registration. */
export function UsersPage() {
  const { me } = useAuth();
  const users = useResource((signal) => api.auth.users({ signal }), []);
  const [dialog, setDialog] = useState<Dialogs>(null);
  const [flash, setFlash] = useState<{ tone: 'success' | 'critical'; text: string } | null>(null);
  const [busyUser, setBusyUser] = useState<string | null>(null);

  const run = async (username: string, action: () => Promise<string>) => {
    setBusyUser(username);
    setFlash(null);
    try {
      setFlash({ tone: 'success', text: await action() });
      users.reload();
    } catch (error) {
      const e = toApiError(error);
      const d = describeError(e);
      setFlash({ tone: 'critical', text: e.kind === 'http' && e.status !== null && e.status < 500 && e.status !== 401 && e.status !== 429 ? e.message : `${d.title}. ${d.detail}`.trim() });
    } finally {
      setBusyUser(null);
    }
  };

  const rows = users.data?.items ?? [];
  return (
    <>
      <PageHeader title="Users" description="Create accounts, change roles, deactivate people who leave, reset passwords and end sessions. Passwords are never shown or recoverable: a reset sets a new one."
        actions={<><Button icon={RefreshCw} onClick={users.reload}>Refresh</Button><Button variant="primary" icon={ShieldCheck} onClick={() => setDialog({ kind: 'create' })}>Create user</Button></>} />
      {flash ? <Banner tone={flash.tone} title={flash.tone === 'success' ? undefined : 'That did not work'}>{flash.text}</Banner> : null}
      <Card>
        {!users.data && users.error ? <ErrorState error={users.error} onRetry={users.reload} />
          : !users.data ? <LoadingRows label="Loading users" />
          : rows.length === 0 ? <EmptyState icon={Briefcase} title="No accounts">Create the first user.</EmptyState> : (
            <>
              {users.error ? <div className="card-body"><ErrorBanner error={users.error} onRetry={users.reload} /></div> : null}
              <div className="table-wrap">
                <table className="table" data-stack="true">
                  <caption className="visually-hidden">Accounts</caption>
                  <thead><tr><th scope="col">User</th><th scope="col">Role</th><th scope="col">Status</th><th scope="col">Last sign-in</th><th scope="col" className="num">Sessions</th><th scope="col">Actions</th></tr></thead>
                  <tbody>
                    {rows.map((u) => {
                      const self = u.analyst_id === me?.analyst_id;
                      const busy = busyUser === u.analyst_id;
                      const manageable = u.has_password && u.username !== null;
                      return (
                        <tr key={u.analyst_id}>
                          <td data-label="User"><strong>{u.display_name ?? u.analyst_id}</strong><div className="muted mono-id">{u.analyst_id}{self ? ' (you)' : ''}</div></td>
                          <td data-label="Role">
                            {self || !manageable ? <Badge tone="accent">{u.role}</Badge> : (
                              <select className="select" aria-label={`Role of ${u.analyst_id}`} value={u.role} disabled={busy}
                                onChange={(e) => void run(u.analyst_id, async () => { await api.auth.updateUser(u.analyst_id, { role: e.target.value as Role }); return `${u.analyst_id} is now ${e.target.value}.`; })}>
                                {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                              </select>
                            )}
                          </td>
                          <td data-label="Status">
                            <Badge tone={u.active ? 'success' : 'neutral'}>{u.active ? 'Active' : 'Deactivated'}</Badge>
                            {!u.has_password ? <div className="muted">API token only (no password)</div> : null}
                          </td>
                          <td data-label="Last sign-in"><Time value={u.last_login_at} /></td>
                          <td data-label="Sessions" className="num">{u.active_sessions}</td>
                          <td data-label="Actions">
                            <div className="row-actions">
                              {manageable && !self ? (
                                <Button size="sm" icon={u.active ? X : ShieldCheck} disabled={busy}
                                  onClick={() => void run(u.analyst_id, async () => { await api.auth.updateUser(u.analyst_id, { active: !u.active }); return `${u.analyst_id} is now ${u.active ? 'deactivated and signed out everywhere' : 'active'}.`; })}>
                                  {u.active ? 'Deactivate' : 'Activate'}
                                </Button>
                              ) : null}
                              {manageable ? <Button size="sm" icon={KeyRound} disabled={busy} onClick={() => setDialog({ kind: 'reset', row: u })}>Reset password</Button> : null}
                              {manageable && u.active_sessions > 0 ? (
                                <Button size="sm" icon={LogOut} disabled={busy}
                                  onClick={() => void run(u.analyst_id, async () => { const r = await api.auth.revokeSessions(u.analyst_id); return `Ended ${r.revoked} session${r.revoked === 1 ? '' : 's'} of ${u.analyst_id}.`; })}>
                                  End sessions
                                </Button>
                              ) : null}
                              {!manageable ? <Button size="sm" icon={KeyRound} disabled={busy} onClick={() => setDialog({ kind: 'create' })}>Give a password…</Button> : null}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </>
          )}
      </Card>
      <Card>
        <CardHeader title="Roles" />
        <CardBody>
          <ul className="stack" role="list">{ROLES.map((r) => <li key={r}><Badge tone="accent">{r}</Badge> {ROLE_HELP[r]}</li>)}</ul>
        </CardBody>
      </Card>
      {dialog?.kind === 'create' ? <CreateDialog onClose={() => setDialog(null)} onDone={(text) => { setDialog(null); setFlash({ tone: 'success', text }); users.reload(); }} /> : null}
      {dialog?.kind === 'reset' ? <ResetDialog row={dialog.row} onClose={() => setDialog(null)} onDone={(text) => { setDialog(null); setFlash({ tone: 'success', text }); users.reload(); }} /> : null}
    </>
  );
}

function CreateDialog({ onClose, onDone }: { onClose: () => void; onDone: (text: string) => void }) {
  const [username, setUsername] = useState('');
  const [display, setDisplay] = useState('');
  const [role, setRole] = useState<Role>('analyst');
  const [password, setPassword] = useState('');
  const [problems, setProblems] = useState<Record<string, string>>({});
  const [failure, setFailure] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const name = username.trim().toLowerCase();
    const next: Record<string, string> = {};
    if (!USERNAME_RE.test(name)) next.username = 'Use 3 to 32 characters: lower-case letters, digits, dot, underscore or hyphen.';
    if (password.length < 12) next.password = 'The password must be at least 12 characters.';
    else if (name.length >= 3 && password.toLowerCase().includes(name)) next.password = 'The password must not contain the username.';
    setProblems(next);
    setFailure(null);
    if (Object.keys(next).length) return;
    setBusy(true);
    try {
      await api.auth.createUser({ username: name, role, password, ...(display.trim() ? { display_name: display.trim() } : {}) });
      onDone(`Created ${name} as ${role}. Give them the password through a private channel; they can change it under Settings.`);
    } catch (error) {
      setFailure(toApiError(error).message);
      setBusy(false);
    }
  };

  return (
    <Dialog title="Create user" onClose={onClose} busy={busy}
      footer={<><Button onClick={onClose} disabled={busy}>Cancel</Button><Button variant="primary" type="submit" form="create-user-form" loading={busy}>Create user</Button></>}>
      <form id="create-user-form" className="stack" onSubmit={submit} noValidate>
        {failure ? <Banner tone="critical" title="The account was not created">{failure}</Banner> : null}
        <TextField label="Username" name="username" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" autoCapitalize="none" spellCheck={false} required error={problems.username}
          hint="Used to sign in. If an existing API-token analyst has this id, they keep their history and get this password." data-autofocus />
        <TextField label="Display name" name="display-name" value={display} onChange={(e) => setDisplay(e.target.value)} autoComplete="off" maxLength={100} hint="Optional." />
        <SelectField label="Role" value={role} onChange={(e) => setRole(e.target.value as Role)} hint={ROLE_HELP[role]}>
          {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
        </SelectField>
        <PasswordField label="Initial password" name="new-password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" required error={problems.password} hint={PASSWORD_HELP} />
      </form>
    </Dialog>
  );
}

function ResetDialog({ row, onClose, onDone }: { row: AccountRow; onClose: () => void; onDone: (text: string) => void }) {
  const [password, setPassword] = useState('');
  const [problem, setProblem] = useState<string | undefined>();
  const [failure, setFailure] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setFailure(null);
    if (password.length < 12) { setProblem('The password must be at least 12 characters.'); return; }
    setProblem(undefined);
    setBusy(true);
    try {
      await api.auth.resetPassword(row.analyst_id, password);
      onDone(`Password of ${row.analyst_id} reset; their other sessions were ended. Give them the new password privately.`);
    } catch (error) {
      setFailure(toApiError(error).message);
      setBusy(false);
    }
  };

  return (
    <Dialog title={`Reset password for ${row.analyst_id}`} onClose={onClose} busy={busy}
      footer={<><Button onClick={onClose} disabled={busy}>Cancel</Button><Button variant="primary" type="submit" form="reset-form" loading={busy}>Reset password</Button></>}>
      <form id="reset-form" className="stack" onSubmit={submit} noValidate>
        {failure ? <Banner tone="critical" title="The password was not reset">{failure}</Banner> : null}
        <p className="muted">All of this person's sessions end immediately. The old password stops working.</p>
        <PasswordField label="New password" name="new-password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" required error={problem} hint={PASSWORD_HELP} data-autofocus />
      </form>
    </Dialog>
  );
}
