import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { JobStatusBadge, SeverityBadge } from './Badge';

describe('badges', () => {
  it('always spell the severity out, never colour alone', () => {
    render(<SeverityBadge severity="critical" />);
    expect(screen.getByText('Critical')).toBeInTheDocument();
  });
  it('distinguishes critical (solid) from high (outlined) without relying on colour', () => {
    const { container, rerender } = render(<SeverityBadge severity="critical" />);
    expect(container.querySelector('.badge')?.getAttribute('data-solid')).toBe('true');
    rerender(<SeverityBadge severity="high" />);
    expect(container.querySelector('.badge')?.getAttribute('data-solid')).toBeNull();
  });
  it('shows a dash when severity is missing and plain text for unknown values', () => {
    const { rerender } = render(<SeverityBadge severity={null} />);
    expect(screen.getByText('—')).toBeInTheDocument();
    rerender(<SeverityBadge severity="catastrophic" />);
    expect(screen.getByText('Catastrophic')).toBeInTheDocument();
  });
  it('humanizes job statuses', () => {
    render(<JobStatusBadge status="timed_out" />);
    expect(screen.getByText('Timed out')).toBeInTheDocument();
  });
});
