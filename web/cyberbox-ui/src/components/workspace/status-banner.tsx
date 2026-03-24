import type { ReactNode } from 'react';

import { cn } from '@/lib/utils';

type WorkspaceStatusTone = 'primary' | 'warning' | 'danger' | 'success' | 'info' | 'neutral';

const toneClassName: Record<WorkspaceStatusTone, string> = {
  primary: 'border-primary/20 bg-primary/10 text-primary',
  warning: 'border-amber-500/20 bg-amber-500/10 text-amber-100',
  danger: 'border-destructive/20 bg-destructive/10 text-destructive',
  success: 'border-emerald-500/20 bg-emerald-500/10 text-emerald-100',
  info: 'border-sky-500/20 bg-sky-500/10 text-sky-100',
  neutral: 'border-border/70 bg-background/35 text-foreground',
};

interface WorkspaceStatusBannerProps {
  children: ReactNode;
  tone?: WorkspaceStatusTone;
  className?: string;
}

export function WorkspaceStatusBanner({
  children,
  tone = 'primary',
  className,
}: WorkspaceStatusBannerProps) {
  return (
    <div
      role={tone === 'danger' || tone === 'warning' ? 'alert' : 'status'}
      className={cn(
        'rounded-lg border px-3 py-2 text-xs',
        toneClassName[tone],
        className,
      )}
    >
      {children}
    </div>
  );
}
