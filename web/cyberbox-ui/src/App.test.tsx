import type { ReactNode } from 'react';
import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { useAuthMock } = vi.hoisted(() => ({
  useAuthMock: vi.fn(),
}));

vi.mock('./contexts/AuthContext', () => ({
  AuthProvider: ({ children }: { children: ReactNode }) => children,
  useAuth: () => useAuthMock(),
}));

vi.mock('./contexts/ThemeContext', () => ({
  ThemeProvider: ({ children }: { children: ReactNode }) => children,
}));

vi.mock('./AuthenticatedApp', () => ({
  AuthenticatedApp: () => <div>Authenticated app stub</div>,
}));

vi.mock('./pages/SignIn', () => ({
  SignIn: () => <div>Sign in stub</div>,
}));

import App from './App';

describe('App auth gate', () => {
  beforeEach(() => {
    useAuthMock.mockReset();
  });

  it('shows the authenticating loading surface while auth is resolving', () => {
    useAuthMock.mockReturnValue({
      isAuthenticated: false,
      isLoading: true,
    });

    render(<App />);

    expect(screen.getByText(/authenticating/i)).toBeInTheDocument();
    expect(screen.getByText(/establishing your security workspace and syncing tenant context/i)).toBeInTheDocument();
    expect(screen.queryByText('Sign in stub')).not.toBeInTheDocument();
    expect(screen.queryByText('Authenticated app stub')).not.toBeInTheDocument();
  });

  it('shows the sign-in surface when auth is not established', async () => {
    useAuthMock.mockReturnValue({
      isAuthenticated: false,
      isLoading: false,
    });

    render(<App />);

    expect(await screen.findByText('Sign in stub')).toBeInTheDocument();
    expect(screen.queryByText(/authenticating/i)).not.toBeInTheDocument();
    expect(screen.queryByText('Authenticated app stub')).not.toBeInTheDocument();
  });

  it('shows the authenticated shell when auth is established', async () => {
    useAuthMock.mockReturnValue({
      isAuthenticated: true,
      isLoading: false,
    });

    render(<App />);

    expect(await screen.findByText('Authenticated app stub')).toBeInTheDocument();
    expect(screen.queryByText('Sign in stub')).not.toBeInTheDocument();
  });
});
