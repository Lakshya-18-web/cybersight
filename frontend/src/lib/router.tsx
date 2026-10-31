import {
  createContext, useCallback, useContext, useEffect, useMemo, useState,
  type AnchorHTMLAttributes, type MouseEvent, type ReactNode,
} from 'react';

/** A very small History-API router: path patterns with :params, links that do not reload the page, and the query string as state. */

export type Params = Record<string, string>;

/** Match "/cases/:id" against "/cases/abc". Exact match only (a trailing slash is ignored); returns the params or null. */
export function matchPath(pattern: string, pathname: string): Params | null {
  const segments = (p: string) => p.split('/').filter((part) => part !== '');
  const a = segments(pattern);
  const b = segments(pathname);
  if (a.length !== b.length) return null;
  const params: Params = {};
  for (let i = 0; i < a.length; i++) {
    const want = a[i] as string;
    const got = b[i] as string;
    if (want.startsWith(':')) {
      try { params[want.slice(1)] = decodeURIComponent(got); } catch { return null; }
    } else if (want !== got) {
      return null;
    }
  }
  return params;
}

export interface RouteDef {
  path: string;
  title: string;
  render: () => ReactNode;
}

export function findRoute(routes: readonly RouteDef[], pathname: string): { route: RouteDef; params: Params } | null {
  for (const route of routes) {
    const params = matchPath(route.path, pathname);
    if (params) return { route, params };
  }
  return null;
}

interface RouterState { pathname: string; search: string }
interface RouterApi extends RouterState {
  navigate: (to: string, options?: { replace?: boolean }) => void;
}

const RouterContext = createContext<RouterApi | null>(null);
const ParamsContext = createContext<Params>({});

function readLocation(): RouterState {
  return { pathname: window.location.pathname, search: window.location.search };
}

export function Router({ children }: { children: ReactNode }) {
  const [state, setState] = useState<RouterState>(readLocation);

  useEffect(() => {
    const onPop = () => setState(readLocation());
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  }, []);

  const navigate = useCallback((to: string, options?: { replace?: boolean }) => {
    const target = new URL(to, window.location.origin);
    if (target.origin !== window.location.origin) { window.location.assign(to); return; }
    const next = `${target.pathname}${target.search}${target.hash}`;
    const current = `${window.location.pathname}${window.location.search}${window.location.hash}`;
    if (next !== current) {
      if (options?.replace) window.history.replaceState(null, '', next);
      else window.history.pushState(null, '', next);
    }
    setState({ pathname: target.pathname, search: target.search });
  }, []);

  const value = useMemo<RouterApi>(() => ({ ...state, navigate }), [state, navigate]);
  return <RouterContext.Provider value={value}>{children}</RouterContext.Provider>;
}

function useRouter(): RouterApi {
  const ctx = useContext(RouterContext);
  if (!ctx) throw new Error('Router is missing');
  return ctx;
}

export function useLocation(): RouterState { const { pathname, search } = useRouter(); return { pathname, search }; }
export function useNavigate() { return useRouter().navigate; }
export function useParams(): Params { return useContext(ParamsContext); }

/** The query string as URLSearchParams plus a setter. Setting replaces the history entry by default so filters do not fill the back stack. */
export function useSearchParams(): [URLSearchParams, (next: Record<string, string | null | undefined>, options?: { replace?: boolean }) => void] {
  const { pathname, search, navigate } = useRouter();
  const params = useMemo(() => new URLSearchParams(search), [search]);
  const set = useCallback((next: Record<string, string | null | undefined>, options?: { replace?: boolean }) => {
    const out = new URLSearchParams(search);
    for (const [k, v] of Object.entries(next)) {
      if (v === null || v === undefined || v === '') out.delete(k); else out.set(k, v);
    }
    const qs = out.toString();
    navigate(`${pathname}${qs ? `?${qs}` : ''}`, { replace: options?.replace ?? true });
  }, [pathname, search, navigate]);
  return [params, set];
}

export function Routes({ routes, notFound }: { routes: readonly RouteDef[]; notFound: () => ReactNode }) {
  const { pathname } = useRouter();
  const found = findRoute(routes, pathname);
  return <ParamsContext.Provider value={found?.params ?? {}}>{found ? found.route.render() : notFound()}</ParamsContext.Provider>;
}

type LinkProps = Omit<AnchorHTMLAttributes<HTMLAnchorElement>, 'href'> & { to: string; replace?: boolean };

export function Link({ to, replace, onClick, children, ...rest }: LinkProps) {
  const { navigate } = useRouter();
  const handle = (event: MouseEvent<HTMLAnchorElement>) => {
    onClick?.(event);
    if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || rest.target === '_blank') return;
    event.preventDefault();
    navigate(to, replace ? { replace: true } : undefined);
  };
  return <a {...rest} href={to} onClick={handle}>{children}</a>;
}

/** A link that marks itself with aria-current="page" when the current path is `to` or (unless `end`) below it. */
export function NavLink({ to, end, ...rest }: LinkProps & { end?: boolean }) {
  const { pathname } = useRouter();
  const active = end ? pathname === to : pathname === to || pathname.startsWith(`${to}/`);
  return <Link to={to} {...rest} {...(active ? { 'aria-current': 'page' as const } : {})} />;
}
