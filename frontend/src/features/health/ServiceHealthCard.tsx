import type { ProviderHealth } from '../../api/types';
import { Badge } from '../../components/ui/Badge';
import { Card, CardHeader } from '../../components/ui/Card';
import { useHealth } from '../../hooks/useHealth';
import { humanize } from '../../lib/format';
import { Link } from '../../lib/router';
import { servicesFrom, STATE_TONE } from '../../lib/serviceHealth';

/** System health from what the API reports about each service. `providers` is GET /providers; when it failed, only the API's own readiness answer is used and the rest say unknown. */
export function ServiceHealthCard({ providers }: { providers: ProviderHealth | undefined }) {
  const health = useHealth();
  const services = servicesFrom(health, providers);
  return (
    <Card>
      <CardHeader title="System health" description="Each row comes from what the API reports for that service." actions={<Link to="/system">Details</Link>} />
      <ul role="list" className="service-list">
        {services.map((s) => (
          <li key={s.key}>
            <span className="svc-name"><span className="status-dot" data-state={s.state === 'healthy' ? 'ok' : s.state === 'degraded' ? 'warn' : s.state === 'unavailable' ? 'down' : 'unknown'} aria-hidden="true" /><span>{s.name}<small>{s.detail}</small></span></span>
            <Badge tone={STATE_TONE[s.state]}>{humanize(s.state)}</Badge>
          </li>
        ))}
      </ul>
    </Card>
  );
}
