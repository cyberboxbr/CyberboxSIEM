import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const useAuthMock = vi.fn();

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => useAuthMock(),
}));

import { CommandPalette } from '@/components/CommandPalette';

describe('CommandPalette', () => {
  beforeEach(() => {
    useAuthMock.mockReset();
  });

  it('shows dev bypass actions and triggers them in bypass mode', async () => {
    const onClose = vi.fn();
    const onOpenBypassEditor = vi.fn();
    const resetBypassIdentity = vi.fn();

    useAuthMock.mockReturnValue({
      authMode: 'bypass',
      isAdmin: true,
      isAnalyst: true,
      resetBypassIdentity,
    });

    render(
      <MemoryRouter>
        <CommandPalette
          open
          onClose={onClose}
          onOpenBypassEditor={onOpenBypassEditor}
        />
      </MemoryRouter>,
    );

    const user = userEvent.setup();

    await user.click(screen.getByRole('button', { name: /edit development identity/i }));
    expect(onOpenBypassEditor).toHaveBeenCalledTimes(1);
    expect(onClose).toHaveBeenCalledTimes(1);

    await user.click(screen.getByRole('button', { name: /reset development identity/i }));
    expect(resetBypassIdentity).toHaveBeenCalledTimes(1);
    expect(onClose).toHaveBeenCalledTimes(2);
  });

  it('hides dev bypass actions outside bypass mode', () => {
    useAuthMock.mockReturnValue({
      authMode: 'microsoft',
      isAdmin: true,
      isAnalyst: true,
      resetBypassIdentity: vi.fn(),
    });

    render(
      <MemoryRouter>
        <CommandPalette open onClose={vi.fn()} onOpenBypassEditor={vi.fn()} />
      </MemoryRouter>,
    );

    expect(screen.queryByRole('button', { name: /edit development identity/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /reset development identity/i })).not.toBeInTheDocument();
  });
});
