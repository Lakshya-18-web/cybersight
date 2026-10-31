import { useSyncExternalStore } from 'react';

export type Theme = 'dark' | 'light';
/** Same storage pattern as the sign-in token: this tab's session storage, wrapped so a blocked storage never breaks the page. Dark is the default. */
const KEY = 'cybersight.theme';
const META_COLOR: Record<Theme, string> = { dark: '#081426', light: '#f3f6fb' };

function read(): Theme {
  try { return window.sessionStorage.getItem(KEY) === 'light' ? 'light' : 'dark'; } catch { return 'dark'; }
}

let current: Theme = 'dark';
const listeners = new Set<() => void>();

function apply(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content', META_COLOR[theme]);
}

/** Call once before the first render so the page never flashes the wrong theme. */
export function initTheme(): void {
  current = read();
  apply(current);
}

export function setTheme(next: Theme): void {
  if (next === current) return;
  current = next;
  apply(next);
  try { window.sessionStorage.setItem(KEY, next); } catch { /* the choice lasts until the page is reloaded */ }
  listeners.forEach((l) => l());
}

const subscribe = (l: () => void) => { listeners.add(l); return () => { listeners.delete(l); }; };
export function useTheme(): { theme: Theme; setTheme: (t: Theme) => void; toggle: () => void } {
  const theme = useSyncExternalStore(subscribe, () => current, () => 'dark' as Theme);
  return { theme, setTheme, toggle: () => setTheme(current === 'dark' ? 'light' : 'dark') };
}
