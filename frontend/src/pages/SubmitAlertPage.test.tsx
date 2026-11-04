import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ submitAlert: vi.fn(), submit: { value: true } }));
vi.mock('../api', () => ({
  api: { submitAlert: mocks.submitAlert, getJob: vi.fn().mockResolvedValue({ job_id: 'j1', status: 'queued', attempts: 0, max_attempts: 3, alert_id: 'A-1', alert_set: 's', memory_mode: 'off', submitted_by: 'bob', enqueued_at: null, first_started_at: null, started_at: null, finished_at: null, not_before: null, case_id: null, error_code: null, error_detail: null, result: null, timings: null, usage: null }) },
  sessionStore: { csrf: () => null, setCsrf: () => undefined, onUnauthorized: () => undefined, onCsrfRefresh: () => undefined },
}));
vi.mock('../auth/AuthContext', () => ({ usePermissions: () => ({ read: true, submit: mocks.submit.value, decide: false, admin: false }) }));

import { Router } from '../lib/router';
import { SubmitAlertPage } from './SubmitAlertPage';

const ALERT = {
  alert_id: 'A-1', timestamp: '2017-07-05 14:30:00', flow_id: 'f-1', src_ip: '192.168.10.9', src_port: 40005, dst_ip: '10.0.0.2', dst_port: 22, protocol: 6, detector_score: 0.9,
  'Flow Duration': 1, 'Total Fwd Packets': 2, 'Total Backward Packets': 3, 'Total Length of Fwd Packets': 4, 'Total Length of Bwd Packets': 5, 'Flow Bytes/s': 6, 'Flow Packets/s': 7,
  'Fwd Packet Length Mean': 8, 'Bwd Packet Length Mean': 9, 'Flow IAT Mean': 10, 'SYN Flag Count': 11, 'ACK Flag Count': 12,
};

const page = () => render(<Router><SubmitAlertPage /></Router>);

describe('SubmitAlertPage', () => {
  it('tells a viewer they cannot submit and renders no form', () => {
    mocks.submit.value = false;
    page();
    expect(screen.getByText('Your role cannot submit alerts')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Submit alert' })).toBeNull();
    mocks.submit.value = true;
  });

  it('shows every problem and sends nothing when the form is empty', async () => {
    mocks.submitAlert.mockReset();
    page();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Submit alert' }));
    expect(await screen.findByText(/21 fields need attention/)).toBeInTheDocument();
    expect(mocks.submitAlert).not.toHaveBeenCalled();
  });

  it('fills from pasted JSON and submits the typed body without a client key', async () => {
    mocks.submitAlert.mockReset();
    mocks.submitAlert.mockResolvedValue({ job_id: 'j1', status: 'queued', duplicate: false, dispatch: 'queued', status_url: '/jobs/j1', httpStatus: 202 });
    const user = userEvent.setup();
    page();
    await user.click(screen.getByRole('button', { name: 'Paste JSON' }));
    await user.click(screen.getByLabelText('Alert JSON'));
    await user.paste(JSON.stringify({ alert: ALERT, memory: 'off' }));
    await user.click(screen.getByRole('button', { name: 'Fill the form' }));
    expect((screen.getByLabelText(/Alert ID/) as HTMLInputElement).value).toBe('A-1');
    await user.click(screen.getByRole('button', { name: 'Submit alert' }));
    expect(await screen.findByText('Alert submitted')).toBeInTheDocument();
    expect(mocks.submitAlert).toHaveBeenCalledTimes(1);
    expect(mocks.submitAlert.mock.calls[0]).toEqual([{ alert: ALERT, memory: 'off' }]);
  });
});
