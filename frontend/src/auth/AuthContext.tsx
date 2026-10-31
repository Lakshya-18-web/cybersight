import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { api, credentialStore } from '../api';
import type { Credentials } from '../api/client';
import { toApiError, type ApiError } from '../api/errors';
import type { Me } from '../api/types';

type Status = 'restoring' | 'signedOut' | 'signedIn';

interface AuthValue {
  status: Status;
  me: Me | null;
  /** Why the user is looking at the sign-in screen when it was not their own choice. */
  notice: string | null;
  signIn: (credentials: Credentials, remember: boolean) => Promise<void>;
  signOut: () => void;
}

const AuthContext = createContext<AuthValue | null>(null);
const STORAGE_KEY = 'soc.session-token';

function readStored(): string | null {
  try { return window.sessionStorage.getItem(STORAGE_KEY); } catch { return null; }
}
function writeStored(token: string | null): void {
  try {
    if (token) window.sessionStorage.setItem(STORAGE_KEY, token);
    else window.sessionStorage.removeItem(STORAGE_KEY);
  } catch { /* storage unavailable: the token simply stays in memory */ }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Status>('restoring');
  const [me, setMe] = useState<Me | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const clear = useCallback((why: string | null) => {
    credentialStore.set(null);
    writeStored(null);
    setMe(null);
    setNotice(why);
    setStatus('signedOut');
  }, []);

  useEffect(() => {
    credentialStore.onUnauthorized(() => clear('Your session is no longer valid. Sign in again.'));
    return () => credentialStore.onUnauthorized(null);
  }, [clear]);

  // Pick up a token kept for this tab (the optional "keep me signed in for this tab" choice), and check it still works.
  useEffect(() => {
    const stored = readStored();
    if (!stored) { setStatus('signedOut'); return; }
    const controller = new AbortController();
    credentialStore.set({ kind: 'bearer', token: stored });
    api.me({ signal: controller.signal }).then(
      (who) => { setMe(who); setStatus('signedIn'); },
      (error: unknown) => {
        const e = toApiError(error);
        if (e.isAborted) return;
        credentialStore.set(null);
        writeStored(null);
        setStatus('signedOut');
      },
    );
    return () => controller.abort();
  }, []);

  const signIn = useCallback(async (next: Credentials, remember: boolean) => {
    credentialStore.set(next);
    try {
      const who = await api.me();
      if (remember && next.kind === 'bearer') writeStored(next.token); else writeStored(null);
      setMe(who);
      setNotice(null);
      setStatus('signedIn');
    } catch (error) {
      credentialStore.set(null);
      throw toApiError(error) satisfies ApiError;
    }
  }, []);

  const signOut = useCallback(() => clear(null), [clear]);

  const value = useMemo<AuthValue>(() => ({ status, me, notice, signIn, signOut }), [status, me, notice, signIn, signOut]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('AuthProvider is missing');
  return ctx;
}

/** What the signed-in person may do, as the API itself reports it. Everything is false until /me has answered. */
export function usePermissions(): { read: boolean; submit: boolean; decide: boolean } {
  const { me } = useAuth();
  return me?.permissions ?? { read: false, submit: false, decide: false };
}
