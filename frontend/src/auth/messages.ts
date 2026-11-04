import type { ApiError } from '../api/errors';

export interface Message { title: string; detail?: string }

function wait(seconds: number | null): string {
  if (!seconds) return 'Wait a little while and try again.';
  if (seconds < 90) return `Try again in ${seconds} second${seconds === 1 ? '' : 's'}.`;
  return `Try again in about ${Math.ceil(seconds / 60)} minutes.`;
}

/** What to tell a person whose sign-in (or first-time setup) request failed. A wrong username and a wrong password are deliberately indistinguishable, as on the server. */
export function signInMessage(error: ApiError, setup = false): Message {
  if (error.isUnreachable) return { title: 'Cannot reach the server', detail: 'Check your connection. If the problem continues the API may be starting up (the free hosting tier sleeps when idle); wait a minute and try again.' };
  switch (error.code) {
    case 'invalid_credentials': return { title: 'Invalid username or password.', detail: 'Check both and try again.' };
    case 'rate_limited': return { title: 'Too many attempts', detail: wait(error.retryAfterSeconds) };
    case 'origin_not_allowed': return { title: 'This site is not allowed to sign in', detail: 'The API does not list this web address as an allowed origin. An administrator must add it to WEEK5_ALLOWED_ORIGINS.' };
    case 'bootstrap_forbidden': return { title: 'The setup secret is not correct', detail: 'Copy WEEK5_BOOTSTRAP_TOKEN again from the API service\'s environment settings.' };
    case 'already_bootstrapped': return { title: 'Setup is already finished', detail: 'An administrator already exists. Sign in with that account.' };
    case 'not_found': return setup ? { title: 'First-time setup is not enabled', detail: 'The API only offers it while WEEK5_BOOTSTRAP_TOKEN is set. See docs/AUTHENTICATION.md.' } : { title: 'Sign-in is not available', detail: error.message };
    case 'invalid_input': return { title: 'Check the details', detail: error.message };
    case 'busy': return { title: 'The server is busy', detail: 'Try again in a moment.' };
    case 'store_unavailable': return { title: 'Sign-in is not available right now', detail: 'The database could not be reached, or the sign-in migration has not been applied yet.' };
    default:
      return error.status === 503 ? { title: 'Sign-in is not available right now', detail: 'Try again in a moment.' } : { title: 'Sign-in failed', detail: error.message };
  }
}
