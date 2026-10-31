// Limits and rules the API enforces for analyst notes, feedback and resolution. The page checks them first so a person is told early; the API still decides.
export const NOTE_MAX = 4000;
export const COMMENT_MAX = 2000;
export const REASON_MAX = 1000;
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;

export function validateText(value: string, max: number, required: boolean, label: string): string | undefined {
  const t = value.trim();
  if (required && t.length === 0) return `${label} is required.`;
  if (value.length > max) return `Keep ${label.toLowerCase()} to ${max} characters or fewer.`;
  if (CONTROL.test(value)) return `${label} contains a character that is not allowed.`;
  return undefined;
}

export interface ResolveCheck { allowed: boolean; why: string | null }

/** A case can be closed by hand only when a person is still needed (escalated or needs review) and nothing is waiting for an approval decision. */
export function canResolve(status: string, pendingActions: number): ResolveCheck {
  if (status === 'resolved') return { allowed: false, why: 'This case is already resolved.' };
  if (status === 'auto_closed') return { allowed: false, why: 'This case was closed automatically; there is nothing to resolve.' };
  if (status !== 'escalated' && status !== 'needs_review') return { allowed: false, why: 'Only escalated or needs-review cases can be resolved.' };
  if (pendingActions > 0) return { allowed: false, why: `${pendingActions} proposed action${pendingActions === 1 ? ' is' : 's are'} still waiting for a decision. Decide them first.` };
  return { allowed: true, why: null };
}
