import { useMemo, useState } from 'react';
import {
  Loader2,
  Settings2,
  Shield,
  Sparkles,
} from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { WorkspaceStatusBanner } from '@/components/workspace/status-banner';
import { useAuth } from '@/contexts/AuthContext';

function MicrosoftMark() {
  return (
    <span className="grid h-5 w-5 grid-cols-2 gap-[2px] rounded-[8px] bg-white/85 p-0.5 shadow-sm">
      <span className="rounded-[2px] bg-[#f25022]" />
      <span className="rounded-[2px] bg-[#7fba00]" />
      <span className="rounded-[2px] bg-[#00a4ef]" />
      <span className="rounded-[2px] bg-[#ffb900]" />
    </span>
  );
}

export function SignIn() {
  const { authMode, error: authError, signIn } = useAuth();
  const [error, setError] = useState('');
  const [startingMicrosoft, setStartingMicrosoft] = useState(false);

  const heroPanels = useMemo(
    () => [
      {
        label: 'Identity',
        value: 'Microsoft SSO',
        detail: 'Tenant-aware roles flow in from Entra ID for normal operator access.',
      },
      {
        label: 'Runtime',
        value: authMode === 'microsoft' ? 'Live SSO' : 'Config needed',
        detail: authMode === 'microsoft'
          ? 'This workspace is ready to start Microsoft sign-in.'
          : 'This build is missing Azure auth settings, so the console cannot start SSO yet.',
      },
      {
        label: 'Scope',
        value: 'SOC workspace',
        detail: 'Triage, hunt, response, and admin surfaces share one tenant-aware shell.',
      },
    ],
    [authMode],
  );

  const trustNotes = useMemo(
    () => [
      {
        title: 'Microsoft-first access',
        body: 'Use Microsoft SSO for the real operator flow so the console inherits your assigned tenant roles.',
        icon: Shield,
      },
      {
        title: authMode === 'microsoft' ? 'Clean fallback story' : 'Development bypass only',
        body: authMode === 'microsoft'
          ? 'This console now avoids a fake local-login branch and keeps the sign-in path aligned with the backend capabilities.'
          : 'For local auth_disabled development, enable VITE_AUTH_BYPASS=true instead of depending on a non-existent local login endpoint.',
        icon: Settings2,
      },
    ],
    [authMode],
  );

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
    <div className="relative min-h-screen overflow-hidden bg-[radial-gradient(circle_at_top_left,_hsl(var(--primary)/0.2),_transparent_30%),radial-gradient(circle_at_85%_12%,_hsl(var(--chart-2)/0.16),_transparent_28%),linear-gradient(180deg,_hsl(var(--background)),_hsl(var(--background)))] text-foreground">
      <div className="pointer-events-none absolute inset-0 bg-grid-noise bg-[size:44px_44px] opacity-25" />
      <div className="pointer-events-none absolute left-[-8rem] top-[-6rem] h-72 w-72 rounded-full bg-primary/18 blur-3xl" />
      <div className="pointer-events-none absolute bottom-[-8rem] right-[-5rem] h-80 w-80 rounded-full bg-chart-2/18 blur-3xl" />

      <div className="relative z-10 flex min-h-screen items-center px-4 py-8 sm:px-6 lg:px-10">
        <div className="mx-auto grid w-full max-w-7xl gap-6 xl:grid-cols-[minmax(0,1.1fr)_460px]">
          <section className="relative overflow-hidden rounded-2xl border border-border/70 bg-[radial-gradient(circle_at_top_left,_hsl(var(--chart-2)/0.22),_transparent_34%),radial-gradient(circle_at_80%_18%,_hsl(var(--primary)/0.16),_transparent_30%),linear-gradient(145deg,_hsl(var(--card)),_hsl(var(--card)/0.8))] shadow-shell">
            <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(120deg,transparent,rgba(255,255,255,0.04),transparent)]" />
            <div className="pointer-events-none absolute right-8 top-8 flex rotate-6 flex-col gap-3 opacity-70">
              <div className="rounded-lg border border-white/10 bg-background/25 px-4 py-3 text-sm backdrop-blur">
                <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">SOC access</div>
                <div className="mt-2 font-medium text-foreground">Identity, roles, and tenant scope stay on one truthful path.</div>
              </div>
              <div className="ml-10 flex items-center gap-3 rounded-lg border border-primary/20 bg-primary/10 px-4 py-3 text-sm text-primary backdrop-blur">
                <Sparkles className="h-4 w-4" />
                Cyberbox auth now matches the real backend surface
              </div>
            </div>

            <div className="relative flex h-full flex-col gap-8 p-6 sm:p-8 lg:p-10">
              <div className="flex flex-wrap gap-2">
                <Badge variant="outline" className="border-primary/25 bg-primary/10 text-primary">Cyberbox SIEM</Badge>
                <Badge variant="secondary" className="bg-background/55">Managed security workspace</Badge>
              </div>

              <div className="flex items-center gap-4">
                <div className="flex h-16 w-16 items-center justify-center rounded-lg border border-border/70 bg-background/45 shadow-card">
                  <img src="/cyberboxlogo.png" alt="Cyberbox" className="h-11 w-11 object-contain" />
                </div>
                <div>
                  <div className="font-display text-2xl font-semibold tracking-[0.22em] text-foreground sm:text-3xl">CYBERBOX</div>
                  <div className="text-xs uppercase tracking-[0.32em] text-muted-foreground">Security operations workspace</div>
                </div>
              </div>

              <div className="max-w-3xl">
                <h1 className="font-display text-4xl font-semibold leading-[0.94] tracking-[-0.05em] text-foreground sm:text-[3.5rem]">
                  Open the command center through the path this environment actually supports.
                </h1>
                <p className="mt-4 max-w-2xl text-base leading-7 text-muted-foreground">
                  Microsoft SSO is the primary operator flow. When this build is not configured for Azure auth, the console now tells you that directly instead of sending you into a dead local-login branch.
                </p>
              </div>

              <div className="grid gap-3 sm:grid-cols-3">
                {heroPanels.map((panel) => (
                  <div key={panel.label} className="rounded-xl border border-border/70 bg-background/30 p-5 backdrop-blur">
                    <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">{panel.label}</div>
                    <div className="mt-3 font-display text-2xl font-semibold tracking-[-0.04em] text-foreground">{panel.value}</div>
                    <p className="mt-2 text-sm leading-6 text-muted-foreground">{panel.detail}</p>
                  </div>
                ))}
              </div>

              <div className="grid gap-4 lg:grid-cols-2">
                {trustNotes.map(({ title, body, icon: Icon }) => (
                  <div key={title} className="rounded-xl border border-border/70 bg-card/65 p-5">
                    <div className="flex items-center gap-3">
                      <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-border/70 bg-background/45 text-primary">
                        <Icon className="h-5 w-5" />
                      </div>
                      <div className="font-medium text-foreground">{title}</div>
                    </div>
                    <p className="mt-4 text-sm leading-6 text-muted-foreground">{body}</p>
                  </div>
                ))}
              </div>
            </div>
          </section>

          <Card className="relative overflow-hidden border-border/80 bg-popover/92 shadow-shell backdrop-blur-2xl">
            <div className="pointer-events-none absolute inset-x-0 top-0 h-32 bg-[radial-gradient(circle_at_top,_hsl(var(--primary)/0.18),_transparent_68%)]" />
            <CardHeader className="relative pb-4">
              <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-primary">
                {authMode === 'microsoft' ? 'Microsoft sign-in' : 'Configuration required'}
              </div>
              <CardTitle className="text-3xl">
                {authMode === 'microsoft' ? 'Open your workspace' : 'Finish auth setup first'}
              </CardTitle>
              <CardDescription className="max-w-md text-sm leading-6">
                {authMode === 'microsoft'
                  ? 'Most operators should continue with Microsoft and let the console inherit their assigned roles.'
                  : 'This deployment does not have Microsoft auth configured yet, so the console cannot start an SSO flow from here.'}
              </CardDescription>
            </CardHeader>

            <CardContent className="relative space-y-6">
              {bannerMessage ? <WorkspaceStatusBanner tone="warning">{bannerMessage}</WorkspaceStatusBanner> : null}

              {authMode === 'microsoft' ? (
                <div className="space-y-4">
                  <Button
                    type="button"
                    size="lg"
                    className="w-full justify-center rounded-lg"
                    onClick={() => void handleMicrosoftLogin()}
                    disabled={startingMicrosoft}
                  >
                    {startingMicrosoft ? <Loader2 className="h-4 w-4 animate-spin" /> : <MicrosoftMark />}
                    {startingMicrosoft ? 'Starting Microsoft sign-in...' : 'Continue with Microsoft'}
                  </Button>

                  <div className="rounded-lg border border-border/70 bg-background/35 p-4">
                    <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Recommended path</div>
                    <p className="mt-3 text-sm leading-6 text-muted-foreground">
                      Use Microsoft when your team is onboarded through Entra ID so the console can inherit role claims and tenant scope directly from your existing identity flow.
                    </p>
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  <WorkspaceStatusBanner tone="warning">
                    Microsoft SSO is not configured for this environment.
                  </WorkspaceStatusBanner>

                  <div className="rounded-lg border border-border/70 bg-background/35 p-4">
                    <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Expected settings</div>
                    <p className="mt-3 text-sm leading-6 text-muted-foreground">
                      Set <code>VITE_AZURE_CLIENT_ID</code>, <code>VITE_AZURE_TENANT_ID</code>, and optionally <code>VITE_AZURE_REDIRECT_URI</code>. For a local <code>auth_disabled=true</code> backend, you can also use <code>VITE_AUTH_BYPASS=true</code> instead of a separate login form.
                    </p>
                  </div>

                  <Button
                    type="button"
                    size="lg"
                    variant="outline"
                    className="w-full justify-center rounded-lg"
                    disabled
                  >
                    <Settings2 className="h-4 w-4" />
                    Microsoft SSO unavailable
                  </Button>
                </div>
              )}

              <div className="rounded-lg border border-border/70 bg-background/35 p-4">
                <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Need help?</div>
                <p className="mt-3 text-sm leading-6 text-muted-foreground">
                  Contact Cyberbox Security if you need Entra onboarding, role changes, or a local development auth configuration for this workspace.
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
