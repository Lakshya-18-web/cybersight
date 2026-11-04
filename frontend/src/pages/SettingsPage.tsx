import { api } from '../api';
import { useAuth } from '../auth/AuthContext';
import { LogOut, RefreshCw } from '../components/icons';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Card, CardBody, CardHeader } from '../components/ui/Card';
import { ChangePasswordCard } from '../features/account/ChangePasswordCard';
import { KeyValue } from '../components/ui/KeyValue';
import { PageHeader } from '../components/ui/PageHeader';
import { Async } from '../components/ui/State';
import { config } from '../config';
import { useTheme } from '../lib/theme';
import { useHealth } from '../hooks/useHealth';
import { useResource } from '../hooks/useResource';
import { humanize } from '../lib/format';

export function SettingsPage() {
  const { me, signOut } = useAuth();
  const health = useHealth();
  const info = useResource((signal) => api.health({ signal }), []);
  const { theme, setTheme } = useTheme();
  return (
    <>
      <PageHeader title="Settings" description="Your session, password, appearance and the state of the API. Roles are managed by administrators (Manage users in the account menu)." />
      <div className="grid grid-2">
        <Card>
          <CardHeader title="Session" actions={<Button icon={LogOut} onClick={signOut}>Sign out</Button>} />
          <CardBody>
            <KeyValue items={[
              ['Signed in as', me ? (me.display_name ? `${me.display_name} (${me.username})` : me.username) : null],
              ['Role', me ? <Badge key="r" tone="accent">{me.role}</Badge> : null],
              ['Can read', me ? (me.permissions.read ? 'Yes' : 'No') : null],
              ['Can submit alerts', me ? (me.permissions.submit ? 'Yes' : 'No') : null],
              ['Can approve and reject', me ? (me.permissions.decide ? 'Yes' : 'No') : null],
              ['Can manage users', me ? (me.permissions.admin ? 'Yes' : 'No') : null],
            ]} />
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="API" actions={<Button icon={RefreshCw} onClick={() => { health.refresh(); info.reload(); }}>Check now</Button>} />
          <CardBody>
            <div className="stack">
              <KeyValue items={[
                ['Address', <code key="a">{config.apiBaseUrl}</code>],
                ['Health', <Badge key="h" tone={health.state === 'ok' ? 'success' : health.state === 'down' ? 'critical' : health.state === 'degraded' ? 'warning' : 'neutral'}>{humanize(health.state)}</Badge>],
                ['Detail', health.detail],
                ['Database', health.ready ? (health.ready.database ? 'Reachable' : 'Not reachable') : null],
                ['Queue broker', health.ready ? (health.ready.broker ? 'Reachable' : 'Not reachable') : null],
                ['Queue backend', health.ready?.queue_backend ?? null],
              ]} />
              <Async resource={info}>
                {(h) => <KeyValue items={[['Authentication mode', humanize(h.auth_mode)], ['Liveness', humanize(h.status)]]} />}
              </Async>
            </div>
          </CardBody>
        </Card>
      </div>
      <ChangePasswordCard />
      <Card>
        <CardHeader title="Appearance" description="Applies to every page. Kept for this browser tab only." />
        <CardBody>
          <div className="segmented" role="group" aria-label="Theme">
            <button type="button" aria-pressed={theme === 'dark'} onClick={() => setTheme('dark')}>Dark</button>
            <button type="button" aria-pressed={theme === 'light'} onClick={() => setTheme('light')}>Light</button>
          </div>
        </CardBody>
      </Card>
      <Card>
        <CardHeader title="Notifications and other settings" />
        <CardBody><p className="muted">The bell in the top bar counts pending approvals, escalated and review cases and failed jobs from the API. There are no notification preferences, e-mail or webhook settings in the API, so none are offered. The model and the queue are managed on the server, outside this console.</p></CardBody>
      </Card>
      <Card>
        <CardHeader title="About this console" />
        <CardBody>
          <KeyValue items={[
            ['Product', 'CyberSight: See threats sooner. Respond smarter.'],
            ['Version', config.appVersion],
            ['Data', 'Everything shown comes from the API; the console stores nothing about your cases.'],
            ['Token handling', 'Held in this tab’s memory (or this tab’s session storage if you chose to stay signed in). It is not in the page source or any bundle.'],
          ]} />
        </CardBody>
      </Card>
    </>
  );
}
