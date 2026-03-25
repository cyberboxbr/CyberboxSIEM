import { useState } from 'react';
import { Loader2, Settings2 } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { WorkspaceStatusBanner } from '@/components/workspace/status-banner';
import { useAuth } from '@/contexts/AuthContext';

function MicrosoftMark() {
  return (
    <span className="grid h-4 w-4 grid-cols-2 gap-[1.5px] rounded-sm bg-white/85 p-0.5">
      <span className="rounded-[1px] bg-[#f25022]" />
      <span className="rounded-[1px] bg-[#7fba00]" />
      <span className="rounded-[1px] bg-[#00a4ef]" />
      <span className="rounded-[1px] bg-[#ffb900]" />
    </span>
  );
}

export function SignIn() {
  const { authMode, error: authError, signIn } = useAuth();
  const [error, setError] = useState('');
  const [startingMicrosoft, setStartingMicrosoft] = useState(false);

  const bannerMessage = error || authError;

  const handleMicrosoftLogin = async () => {
    setError('');
    setStartingMicrosoft(true);
    try {
      await signIn();
    } catch (cause) {
      setStartingMicrosoft(false);
      setError(cause instanceof Error ? cause.message : 'Microsoft sign-in could not start.');
    }
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center bg-background text-foreground">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_30%_20%,_hsl(var(--primary)/0.12),_transparent_40%)]" />

      <div className="relative z-10 w-full max-w-sm px-6">
        {/* Logo + brand */}
        <div className="flex flex-col items-center">
          <img src="/cyberboxlogo.png" alt="Cyberbox" className="h-12 w-12 object-contain" />
          <div className="mt-4 text-center">
            <span className="text-sm font-bold uppercase tracking-[0.18em] text-foreground">
              CYBER<span className="text-[#00FFA3]">BOX</span> SECURITY
            </span>
          </div>
          <p className="mt-2 text-center text-xs text-muted-foreground">
            Security operations workspace
          </p>
        </div>

        {/* Sign-in card */}
        <div className="mt-8 rounded-xl border border-border/70 bg-card/80 p-6 shadow-card backdrop-blur-xl">
          {bannerMessage && (
            <WorkspaceStatusBanner tone="warning" className="mb-4">{bannerMessage}</WorkspaceStatusBanner>
          )}

          {authMode === 'microsoft' ? (
            <div className="space-y-4">
              <Button
                type="button"
                className="w-full justify-center"
                onClick={() => void handleMicrosoftLogin()}
                disabled={startingMicrosoft}
              >
                {startingMicrosoft ? <Loader2 className="h-4 w-4 animate-spin" /> : <MicrosoftMark />}
                {startingMicrosoft ? 'Connecting...' : 'Sign in with Microsoft'}
              </Button>
              <p className="text-center text-[10px] text-muted-foreground">
                Roles and tenant scope are inherited from Entra ID.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="rounded-lg border border-border/70 bg-background/35 px-3 py-2.5 text-xs text-muted-foreground">
                <p>Microsoft SSO is not configured. Set <code className="text-foreground">VITE_AZURE_CLIENT_ID</code> and <code className="text-foreground">VITE_AZURE_TENANT_ID</code> to enable.</p>
                <p className="mt-1.5">For development, use <code className="text-foreground">VITE_AUTH_BYPASS=true</code>.</p>
              </div>
              <Button type="button" variant="outline" className="w-full justify-center" disabled>
                <Settings2 className="h-3.5 w-3.5" />
                SSO unavailable
              </Button>
            </div>
          )}
        </div>

        <p className="mt-6 text-center text-[10px] text-muted-foreground">
          Contact Cyberbox Security for onboarding or access issues.
        </p>
      </div>
    </div>
  );
}
