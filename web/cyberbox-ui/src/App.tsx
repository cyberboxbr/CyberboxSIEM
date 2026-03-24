import { Suspense, lazy } from 'react';
import { BrowserRouter } from 'react-router-dom';

import { AuthProvider, useAuth } from './contexts/AuthContext';
import { ThemeProvider } from './contexts/ThemeContext';

const AuthenticatedApp = lazy(() =>
  import('./AuthenticatedApp').then((module) => ({ default: module.AuthenticatedApp })),
);
const SignIn = lazy(() => import('./pages/SignIn').then((module) => ({ default: module.SignIn })));

function SurfaceLoading({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden px-6 py-16">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_left,_hsl(var(--primary)/0.2),_transparent_36%),radial-gradient(circle_at_bottom_right,_hsl(var(--accent)/0.16),_transparent_32%),linear-gradient(180deg,_hsl(var(--background)),_hsl(var(--background)))]" />
      <div className="relative z-10 w-full max-w-md rounded-[28px] border border-border/70 bg-card/85 p-10 text-center shadow-shell backdrop-blur-2xl">
        <div className="mx-auto flex w-fit items-center gap-3 rounded-full border border-white/10 bg-white/5 px-4 py-2">
          <img src="/cyberboxlogo.png" alt="Cyberbox" className="h-10 w-10 object-contain" />
          <span className="font-display text-lg font-semibold tracking-[0.18em] text-foreground">CYBERBOX</span>
        </div>
        <p className="mt-6 text-sm uppercase tracking-[0.28em] text-primary">{title}</p>
        <p className="mt-3 text-sm text-muted-foreground">
          {description}
        </p>
      </div>
    </div>
  );
}

function AuthGate() {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <SurfaceLoading
        title="Authenticating"
        description="Establishing your security workspace and syncing tenant context."
      />
    );
  }

  if (!isAuthenticated) {
    return (
      <Suspense fallback={<SurfaceLoading title="Loading sign-in" description="Preparing the Cyberbox access surface." />}>
        <SignIn />
      </Suspense>
    );
  }

  return (
    <Suspense fallback={<SurfaceLoading title="Loading workspace" description="Preparing the Cyberbox command center shell." />}>
      <AuthenticatedApp />
    </Suspense>
  );
}

function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <BrowserRouter>
          <AuthGate />
        </BrowserRouter>
      </AuthProvider>
    </ThemeProvider>
  );
}

export default App;
