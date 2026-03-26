import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const useAuthMock = vi.fn();

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => useAuthMock(),
}));

import { SignIn } from '@/pages/SignIn';

describe('SignIn', () => {
  beforeEach(() => {
    useAuthMock.mockReset();
  });

  it('shows setup guidance when Microsoft auth is not configured', () => {
    useAuthMock.mockReturnValue({
      authMode: 'unconfigured',
      error: '',
      signIn: vi.fn(),
    });

    render(<SignIn />);

    expect(screen.getByText(/sso is not configured/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /sso unavailable/i })).toBeDisabled();
  });

  it('starts Microsoft sign-in from the configured state', async () => {
    const signIn = vi.fn().mockResolvedValue(undefined);

    useAuthMock.mockReturnValue({
      authMode: 'microsoft',
      error: '',
      signIn,
    });

    render(<SignIn />);

    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: /sign in with microsoft/i }));

    expect(signIn).toHaveBeenCalledTimes(1);
  });

  it('surfaces Microsoft sign-in startup errors', async () => {
    const signIn = vi.fn().mockRejectedValue(new Error('Popup blocked by browser policy.'));

    useAuthMock.mockReturnValue({
      authMode: 'microsoft',
      error: '',
      signIn,
    });

    render(<SignIn />);

    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: /sign in with microsoft/i }));

    expect(await screen.findByText('Popup blocked by browser policy.')).toBeInTheDocument();
  });
});
