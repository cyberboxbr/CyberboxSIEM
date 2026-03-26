import { Suspense, lazy } from 'react';
import { BrowserRouter } from 'react-router-dom';

import { AuthProvider, useAuth } from './contexts/AuthContext';
import { ThemeProvider } from './contexts/ThemeContext';

const AuthenticatedApp = lazy(() =>
  import('./AuthenticatedApp').then((module) => ({ default: module.AuthenticatedApp })),
);
const SignIn = lazy(() => import('./pages/SignIn').then((module) => ({ default: module.SignIn })));

function SurfaceLoading({ label }: { label: string }) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <div className="flex flex-col items-center gap-5">
        <img src="/cyberboxlogo.png" alt="Cyberbox" className="h-10 w-10 animate-pulse object-contain" />
        <span className="text-xs font-bold uppercase tracking-[0.18em] text-foreground">
          CYBER<span className="text-[#00F4A3]">BOX</span>
        </span>
        <div className="flex items-center gap-2">
          <div className="h-1 w-1 animate-pulse rounded-full bg-primary" />
          <div className="h-1 w-1 animate-pulse rounded-full bg-primary [animation-delay:150ms]" />
          <div className="h-1 w-1 animate-pulse rounded-full bg-primary [animation-delay:300ms]" />
        </div>
        <span className="text-[10px] uppercase tracking-[0.2em] text-muted-foreground">{label}</span>
      </div>
    </div>
  );
}

function AuthGate() {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return <SurfaceLoading label="Authenticating" />;
  }

  if (!isAuthenticated) {
    return (
      <Suspense fallback={<SurfaceLoading label="Loading" />}>
        <SignIn />
      </Suspense>
    );
  }

  return (
    <Suspense fallback={<SurfaceLoading label="Loading workspace" />}>
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
