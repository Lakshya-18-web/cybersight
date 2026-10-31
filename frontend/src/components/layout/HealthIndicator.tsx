import { useHealth } from '../../hooks/useHealth';
import { RefreshCw } from '../icons';
import { Icon } from '../ui/Icon';

const LABEL = { checking: 'Checking API', ok: 'API ready', degraded: 'API degraded', down: 'API unreachable' } as const;

/** The live state of the backend, from GET /health/ready (never assumed). Click to check again. */
export function HealthIndicator() {
  const health = useHealth();
  return (
    <button type="button" className="health" data-state={health.state} onClick={health.refresh} title={`${health.detail} Click to check again.`} aria-label={`${LABEL[health.state]}. ${health.detail} Activate to check again.`}>
      <span className="health-dot" aria-hidden="true" />
      <span className="hide-narrow health-label">{LABEL[health.state]}</span>
      <Icon icon={RefreshCw} size={13} />
    </button>
  );
}
