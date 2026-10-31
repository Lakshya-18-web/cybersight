import { config } from '../config';
import { HttpClient, type Credentials } from './client';
import { createApi } from './endpoints';

// The one client the app uses. Credentials live in this module's memory only (see auth/AuthContext for the optional per-tab copy).
let credentials: Credentials | null = null;
let unauthorizedHandler: (() => void) | null = null;

export const credentialStore = {
  get: () => credentials,
  set: (next: Credentials | null) => { credentials = next; },
  onUnauthorized: (handler: (() => void) | null) => { unauthorizedHandler = handler; },
};

export const client = new HttpClient({
  baseUrl: config.apiBaseUrl,
  getCredentials: () => credentials,
  onUnauthorized: () => unauthorizedHandler?.(),
});

export const api = createApi(client);
