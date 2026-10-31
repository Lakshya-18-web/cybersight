import { useAuth } from './auth/AuthContext';
import { Shell } from './components/layout/Shell';
import { LoadingRows } from './components/ui/State';
import { findRoute, Routes, useLocation, type RouteDef } from './lib/router';
import { AlertsPage } from './pages/AlertsPage';
import { AnalyticsPage } from './pages/AnalyticsPage';
import { AuditPage } from './pages/AuditPage';
import { CasesPage } from './pages/CasesPage';
import { EvidencePage } from './pages/EvidencePage';
import { PlaybooksPage } from './pages/PlaybooksPage';
import { ReportsPage } from './pages/ReportsPage';
import { ThreatIntelPage } from './pages/ThreatIntelPage';
import { CaseDetailPage } from './pages/CaseDetailPage';
import { EvaluationPage } from './pages/EvaluationPage';
import { InvestigationsPage } from './pages/InvestigationsPage';
import { JobDetailPage } from './pages/JobDetailPage';
import { JobsPage } from './pages/JobsPage';
import { NotFoundPage } from './pages/NotFoundPage';
import { OverviewPage } from './pages/OverviewPage';
import { SettingsPage } from './pages/SettingsPage';
import { SignInPage } from './pages/SignInPage';
import { SystemPage } from './pages/SystemPage';
import { SubmitAlertPage } from './pages/SubmitAlertPage';

export const ROUTES: readonly RouteDef[] = [
  { path: '/', title: 'Dashboard', render: () => <OverviewPage /> },
  { path: '/alerts', title: 'Alerts', render: () => <AlertsPage /> },
  { path: '/alerts/new', title: 'Submit alert', render: () => <SubmitAlertPage /> },
  { path: '/cases', title: 'Cases', render: () => <CasesPage /> },
  { path: '/evidence', title: 'Evidence', render: () => <EvidencePage /> },
  { path: '/analytics', title: 'Analytics', render: () => <AnalyticsPage /> },
  { path: '/threat-intel', title: 'Threat Intelligence', render: () => <ThreatIntelPage /> },
  { path: '/playbooks', title: 'Playbooks', render: () => <PlaybooksPage /> },
  { path: '/reports', title: 'Reports', render: () => <ReportsPage /> },
  { path: '/cases/:id', title: 'Case', render: () => <CaseDetailPage /> },
  { path: '/investigations', title: 'Investigations', render: () => <InvestigationsPage /> },
  { path: '/jobs', title: 'Jobs', render: () => <JobsPage /> },
  { path: '/jobs/:id', title: 'Job', render: () => <JobDetailPage /> },
  { path: '/audit', title: 'Audit Log', render: () => <AuditPage /> },
  { path: '/system', title: 'System', render: () => <SystemPage /> },
  { path: '/evaluation', title: 'Evaluation', render: () => <EvaluationPage /> },
  { path: '/settings', title: 'Settings', render: () => <SettingsPage /> },
];

export function App() {
  const { status } = useAuth();
  const { pathname } = useLocation();
  if (status === 'restoring') return <div className="auth-page"><LoadingRows rows={3} label="Starting" /></div>;
  if (status === 'signedOut') return <SignInPage />;
  const title = findRoute(ROUTES, pathname)?.route.title ?? 'Not found';
  return (
    <Shell title={title}>
      <Routes routes={ROUTES} notFound={() => <NotFoundPage />} />
    </Shell>
  );
}
