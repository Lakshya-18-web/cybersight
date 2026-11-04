import { useCallback, useRef, useState } from 'react';
import { useAuth, usePermissions } from '../../auth/AuthContext';
import { useDismiss } from '../../hooks/useDismiss';
import { Link } from '../../lib/router';
import { useTheme } from '../../lib/theme';
import { Activity, ChevronDown, Cpu, FileSearch, LogOut, Moon, Settings, ShieldCheck, Sun } from '../icons';
import { Badge } from '../ui/Badge';
import { Icon } from '../ui/Icon';

function initials(id: string | undefined): string {
  const parts = (id ?? '').split(/[^A-Za-z0-9]+/).filter(Boolean);
  const first = parts[0]?.[0] ?? '?';
  return (parts.length > 1 ? first + (parts[1]?.[0] ?? '') : (parts[0]?.slice(0, 2) ?? '?')).toUpperCase();
}

/** The signed-in person (from GET /me), their role, and the pages that are not in the main navigation. */
export function AccountMenu() {
  const { me, signOut } = useAuth();
  const { admin } = usePermissions();
  const { theme, toggle } = useTheme();
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const close = useCallback(() => setOpen(false), []);
  useDismiss(open, close, box, trigger);
  const name = me?.display_name || me?.username || me?.analyst_id || 'Account';
  return (
    <div className="popover-wrap" ref={box}>
      <button ref={trigger} type="button" className="account-btn" aria-expanded={open} aria-controls={open ? 'account-panel' : undefined} aria-label={`Account menu for ${name}`} onClick={() => setOpen((v) => !v)}>
        <span className="avatar" aria-hidden="true">{initials(name)}</span>
        <span className="account-name hide-narrow">{name}</span>
        <Icon icon={ChevronDown} size={14} />
      </button>
      {open ? (
        <div className="popover popover-right" id="account-panel" role="region" aria-label="Account">
          <div className="popover-head">
            <span className="popover-title">{name}</span>
            {me ? <Badge tone="accent">{me.role}</Badge> : null}
          </div>
          <ul role="list" className="popover-list">
            <li><Link to="/settings" onClick={close} className="popover-link"><Icon icon={Settings} />Settings</Link></li>
            {admin ? <li><Link to="/admin/users" onClick={close} className="popover-link"><Icon icon={ShieldCheck} />Manage users</Link></li> : null}
            <li><Link to="/system" onClick={close} className="popover-link"><Icon icon={Activity} />System status</Link></li>
            <li><Link to="/jobs" onClick={close} className="popover-link"><Icon icon={Cpu} />Jobs</Link></li>
            <li><Link to="/investigations" onClick={close} className="popover-link"><Icon icon={FileSearch} />Review queues</Link></li>
            <li className="menu-theme"><button type="button" className="popover-link popover-button" onClick={toggle}><Icon icon={theme === 'dark' ? Sun : Moon} />{theme === 'dark' ? 'Light theme' : 'Dark theme'}</button></li>
            <li><button type="button" className="popover-link popover-button" onClick={() => { close(); signOut(); }}><Icon icon={LogOut} />Sign out</button></li>
          </ul>
        </div>
      ) : null}
    </div>
  );
}
