import { useEffect, useRef, useState, type ReactNode } from 'react';
import { usePermissions } from '../../auth/AuthContext';
import { Link, useLocation } from '../../lib/router';
import { Briefcase, FileSearch, FileText, LayoutDashboard, Menu, Radar, ScrollText, Send, ShieldAlert, TrendingUp, Workflow, X, type LucideIcon } from '../icons';
import { Logo } from '../brand/Logo';
import { NavMore } from './NavMore';
import { Button } from '../ui/Button';
import { Icon } from '../ui/Icon';
import { AccountMenu } from './AccountMenu';
import { HealthIndicator } from './HealthIndicator';
import { Notifications } from './Notifications';
import { ThemeToggle } from './ThemeToggle';

interface NavItem { to: string; label: string; icon: LucideIcon; /** exact match only */ end?: boolean; /** other paths that belong to this destination */ also?: readonly string[]; /** listed under the "More" menu on desktop (every item is listed in the compact menu) */ more?: boolean }

/** The nine destinations. Evidence, Analytics, Threat Intelligence, Playbooks and Reports are built from the API that exists; where the API has no global feed they say so on the page.
 *  Jobs, System status, Settings and the review queues are reached from the account menu and from the pages that link to them. */
export const NAV: readonly NavItem[] = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/alerts', label: 'Alerts', icon: ShieldAlert },
  { to: '/cases', label: 'Cases', icon: Briefcase },
  { to: '/evidence', label: 'Evidence', icon: FileSearch },
  { to: '/analytics', label: 'Analytics', icon: TrendingUp },
  { to: '/threat-intel', label: 'Threat Intelligence', icon: Radar, more: true },
  { to: '/playbooks', label: 'Playbooks', icon: Workflow, also: ['/investigations'], more: true },
  { to: '/reports', label: 'Reports', icon: FileText, also: ['/evaluation'], more: true },
  { to: '/audit', label: 'Audit Log', icon: ScrollText, more: true },
];

const PRIMARY = NAV.filter((n) => !n.more);
const MORE = NAV.filter((n) => n.more);

export function isActive(item: NavItem, pathname: string): boolean {
  const hit = (base: string) => (item.end ? pathname === base : pathname === base || pathname.startsWith(`${base}/`));
  return hit(item.to) || (item.also ?? []).some((p) => pathname === p || pathname.startsWith(`${p}/`));
}

function NavLinkItem({ item, pathname, extra }: { item: NavItem; pathname: string; extra?: boolean }) {
  return (
    <Link to={item.to} className={extra ? 'nav-link nav-link-extra' : 'nav-link'} {...(isActive(item, pathname) ? { 'aria-current': 'page' as const } : {})}>
      <Icon icon={item.icon} size={16} /><span>{item.label}</span>
    </Link>
  );
}

export function Shell({ title, children }: { title: string; children: ReactNode }) {
  const { submit } = usePermissions();
  const { pathname } = useLocation();
  const [navOpen, setNavOpen] = useState(false);
  const mainRef = useRef<HTMLElement>(null);
  const first = useRef(true);
  const menuRef = useRef<HTMLButtonElement>(null);

  // On every page change: set the document title, close the compact menu, and move focus to the page so keyboard and screen-reader users start at the top of the new content.
  useEffect(() => {
    document.title = `${title} · CyberSight`;
    setNavOpen(false);
    if (first.current) { first.current = false; return; }
    mainRef.current?.focus({ preventScroll: true });
    window.scrollTo(0, 0);
  }, [pathname, title]);

  useEffect(() => {
    if (!navOpen) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') { setNavOpen(false); menuRef.current?.focus(); } };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [navOpen]);

  return (
    <div className="app">
      <a className="skip-link" href="#main" onClick={(e) => { e.preventDefault(); mainRef.current?.focus(); }}>Skip to content</a>
      <header className="topnav">
        <div className="topnav-bar">
          <Link to="/" className="brand" aria-label="CyberSight, Security Operations: go to the dashboard"><Logo size={28} subtitle="Security Operations" /></Link>
          <nav className="nav" id="main-nav" data-open={navOpen} aria-label="Main">
            {PRIMARY.map((item) => <NavLinkItem key={item.to} item={item} pathname={pathname} />)}
            {/* Desktop: these four live in the More menu. Compact menu: they are listed here with the rest, and More is hidden. */}
            {MORE.map((item) => <NavLinkItem key={item.to} item={item} pathname={pathname} extra />)}
            <NavMore items={MORE} pathname={pathname} />
          </nav>
          <div className="topnav-end">
            {submit ? <Link to="/alerts/new" className="btn" data-variant="primary" data-size="sm" aria-label="Submit alert"><Icon icon={Send} size={14} /><span className="hide-narrow">Submit alert</span></Link> : null}
            <HealthIndicator />
            <Notifications />
            <ThemeToggle />
            <AccountMenu />
            <Button ref={menuRef} className="menu-button icon-btn" variant="ghost" size="sm" icon={navOpen ? X : Menu} aria-label={navOpen ? 'Close navigation' : 'Open navigation'} aria-expanded={navOpen} aria-controls="main-nav" onClick={() => setNavOpen((v) => !v)} />
          </div>
        </div>
      </header>
      <div className="scrim" data-open={navOpen} onClick={() => setNavOpen(false)} aria-hidden="true" />
      <main id="main" className="content" tabIndex={-1} ref={mainRef}>{children}</main>
      <footer className="app-foot">CyberSight · Proposed actions are never executed against real systems.</footer>
    </div>
  );
}
