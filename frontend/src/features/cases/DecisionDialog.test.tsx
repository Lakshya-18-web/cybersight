import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { ApiError } from '../../api/errors';
import { IDEMPOTENCY_KEY_RE } from '../../lib/ids';

const mocks = vi.hoisted(() => ({ decide: vi.fn() }));
vi.mock('../../api', () => ({ api: { decide: mocks.decide }, sessionStore: { csrf: () => null, setCsrf: () => undefined, onUnauthorized: () => undefined, onCsrfRefresh: () => undefined } }));

import { DecisionDialog } from './DecisionDialog';

const action = { action_id: 'a1', action_type: 'increase_monitoring', target: '10.0.0.2', rationale: 'because' };
const result = { outcome: 'applied', replayed: false, action: { ...action, state: 'approved' }, decision: null, execution: null };

function setup(decision: 'approved' | 'rejected' = 'approved') {
  const onClose = vi.fn();
  const onDecided = vi.fn();
  const onConflict = vi.fn();
  render(<DecisionDialog action={action} decision={decision} onClose={onClose} onDecided={onDecided} onConflict={onConflict} />);
  return { onClose, onDecided, onConflict, user: userEvent.setup() };
}

describe('DecisionDialog', () => {
  it('will not decide without a reason', async () => {
    mocks.decide.mockReset();
    const { user, onDecided } = setup();
    await user.click(screen.getByRole('button', { name: 'Approve' }));
    expect(screen.getByText(/A reason is required/)).toBeInTheDocument();
    expect(mocks.decide).not.toHaveBeenCalled();
    expect(onDecided).not.toHaveBeenCalled();
  });

  it('sends the trimmed reason with a valid Idempotency-Key and reports the result', async () => {
    mocks.decide.mockReset();
    mocks.decide.mockResolvedValue(result);
    const { user, onDecided } = setup();
    await user.type(screen.getByLabelText(/Reason/), '  matches the scan  ');
    await user.click(screen.getByRole('button', { name: 'Approve' }));
    expect(mocks.decide).toHaveBeenCalledTimes(1);
    const [id, decision, reason, key] = mocks.decide.mock.calls[0] as [string, string, string, string];
    expect([id, decision, reason]).toEqual(['a1', 'approved', 'matches the scan']);
    expect(IDEMPOTENCY_KEY_RE.test(key)).toBe(true);
    expect(onDecided).toHaveBeenCalledWith(result);
  });

  it('reuses the same key when the person retries after a failure, so a retry cannot decide twice', async () => {
    mocks.decide.mockReset();
    mocks.decide.mockRejectedValueOnce(new ApiError({ kind: 'network', message: 'down' })).mockResolvedValueOnce(result);
    const { user } = setup();
    await user.type(screen.getByLabelText(/Reason/), 'ok');
    await user.click(screen.getByRole('button', { name: 'Approve' }));
    expect(await screen.findByText('Cannot reach the API')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Approve' }));
    expect(mocks.decide).toHaveBeenCalledTimes(2);
    expect(mocks.decide.mock.calls[0]?.[3]).toBe(mocks.decide.mock.calls[1]?.[3]);
  });

  it('explains a conflict and tells the page to refresh', async () => {
    mocks.decide.mockReset();
    mocks.decide.mockRejectedValue(new ApiError({ kind: 'http', status: 409, code: 'conflict', message: 'the proposal is already approved' }));
    const { user, onConflict } = setup('rejected');
    await user.type(screen.getByLabelText(/Reason/), 'no');
    await user.click(screen.getByRole('button', { name: 'Reject' }));
    expect(await screen.findByText('This action was already decided')).toBeInTheDocument();
    expect(onConflict).toHaveBeenCalledTimes(1);
  });

  it('closes with Escape', async () => {
    const { user, onClose } = setup();
    await user.keyboard('{Escape}');
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
