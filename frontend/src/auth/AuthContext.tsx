import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { api, sessionStore } from '../api';
import { toApiError, type ApiError } from '../api/errors';
import type { AuthSession, Me, Permissions } from '../api/types';

/** restoring: asking the server whether this browser already has a session (page load or refresh). signedOut / signingIn: the sign-in screen. signedIn: the console. */
export type Status = 'restoring' | 'signedOut' | 'signingIn' | 'signedIn';

interface AuthValue {
  status: Status;
  me: Me | null;
  /** Why the user is looking at the sign-in screen when it was not their own choice (session ended, server unreachable). */
  notice: string | null;
  /** Sign in with a username and password. Resolves when signed in; rejects with an ApiError (the caller shows it) and leaves the app signed out. */
  signIn: (username: string, password: string) => Promise<void>;
  /** End the session on the server and here. Never fails from the person's point of view: they are signed out in the browser either way. */
  signOut: () => void;
}

const AuthContext = createContext<AuthValue | null>(null);
const NO_PERMISSIONS: Permissions = { read: false, submit: false, decide: false, admin: false };
const REVALIDATE_MS = 60_000;

function meFrom(session: AuthSession): Me {
  const u = session.user;
  return { analyst_id: u.analyst_id, username: u.username, display_name: u.display_name, role: u.role, active: true, permissions: u.permissions };
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Status>('restoring');
  const [me, setMe] = useState<Me | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const lastChecked = useRef(0);

  const apply = useCallback((session: AuthSession) => {
    sessionStore.setCsrf(session.csrf_token);
    lastChecked.current = Date.now();
    setMe(meFrom(session));
    setNotice(null);
    setStatus('signedIn');
  }, []);

  const clear = useCallback((why: string | null) => {
    sessionStore.setCsrf(null);
    setMe(null);
    setNotice(why);
    setStatus('signedOut');
  }, []);

  // Any request that comes back 401 means the server no longer accepts the session (idle or absolute expiry, revoked, account deactivated): go back to the sign-in screen.
  useEffect(() => {
    sessionStore.onUnauthorized(() => clear('Your session has ended. Sign in again.'));
    sessionStore.onCsrfRefresh(async () => {
      try { apply(await api.auth.session()); return true; } catch { return false; }
    });
    return () => { sessionStore.onUnauthorized(null); sessionStore.onCsrfRefresh(null); };
  }, [apply, clear]);

  // Page load or refresh: the browser still holds the HttpOnly cookie, so ask the server who it belongs to. No token is read from, or written to, any browser storage.
  useEffect(() => {
    const controller = new AbortController();
    api.auth.session({ signal: controller.signal, quiet: true }).then(
      apply,
      (error: unknown) => {
        const e = toApiError(error);
        if (e.isAborted) return;
        clear(e.isUnauthorized ? null : e.isUnreachable ? 'The server could not be reached. Check your connection and sign in again.' : null);
      },
    );
    return () => controller.abort();
  }, [apply, clear]);

  // Coming back to the tab: a session that was ended elsewhere (an administrator revoked it, the password was changed) is noticed now rather than on the next click.
  useEffect(() => {
    if (status !== 'signedIn') return;
    const check = () => {
      if (document.visibilityState !== 'visible' || Date.now() - lastChecked.current < REVALIDATE_MS) return;
      lastChecked.current = Date.now();
      api.auth.session().then(apply, () => { /* a 401 already sent the person to the sign-in screen; other failures are retried on the next focus */ });
    };
    document.addEventListener('visibilitychange', check);
    window.addEventListener('focus', check);
    return () => { document.removeEventListener('visibilitychange', check); window.removeEventListener('focus', check); };
  }, [status, apply]);

  const signIn = useCallback(async (username: string, password: string) => {
    setStatus('signingIn');
    try {
      apply(await api.auth.login(username, password));
    } catch (error) {
      setStatus('signedOut');
      throw toApiError(error) satisfies ApiError;
    }
  }, [apply]);

  const signOut = useCallback(() => {
    void api.auth.logout().catch(() => undefined);      // the request is built (cookie + CSRF header) before the token is dropped on the next line
    clear(null);
  }, [clear]);

  const value = useMemo<AuthValue>(() => ({ status, me, notice, signIn, signOut }), [status, me, notice, signIn, signOut]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('AuthProvider is missing');
  return ctx;
}

/** What the signed-in person may do, as the API itself reports it. Everything is false until the session has been restored. */
export function usePermissions(): Permissions {
  const { me } = useAuth();
  return me?.permissions ?? NO_PERMISSIONS;
}
