import { Link } from '../lib/router';
import { EmptyState } from '../components/ui/State';
import { Card } from '../components/ui/Card';

export function NotFoundPage() {
  return (
    <Card>
      <EmptyState title="Page not found" action={<Link to="/" className="btn" data-variant="primary">Go to Overview</Link>}>That address does not exist in this console.</EmptyState>
    </Card>
  );
}
