import { config } from '../config';
import { HttpClient } from './client';
import { createApi } from './endpoints';

// The one client the app uses. Signing in is a cookie: the server sets an HttpOnly session cookie that this code cannot read and the browser sends by itself (credentials: 'include').
// The only thing kept here, in memory and nowhere else, is the CSRF token the server returned with the session; nothing is written to localStorage, sessionStorage or a readable cookie.
let csrf: string | null = null;
let unauthorizedHandler: (() => void) | null = null;
let csrfRefresher: (() => Promise<boolean>) | null = null;

export const sessionStore = {
  csrf: () => csrf,
  setCsrf: (next: string | null) => { csrf = next; },
  onUnauthorized: (handler: (() => void) | null) => { unauthorizedHandler = handler; },
  onCsrfRefresh: (handler: (() => Promise<boolean>) | null) => { csrfRefresher = handler; },
};

export const client = new HttpClient({
  baseUrl: config.apiBaseUrl,
  getCsrfToken: () => csrf,
  refreshCsrf: () => (csrfRefresher ? csrfRefresher() : Promise.resolve(false)),
  onUnauthorized: () => unauthorizedHandler?.(),
});

export const api = createApi(client);
