import type { ReactNode } from 'react';

import { cn } from '@/lib/utils';

interface WorkspaceEmptyStateProps {
  title: ReactNode;
  body: ReactNode;
  className?: string;
}

export function WorkspaceEmptyState({ title, body, className }: WorkspaceEmptyStateProps) {
  return (
    <div
      className={cn(
        'flex min-h-[140px] flex-col items-center justify-center rounded-lg border border-dashed border-border/80 bg-background/30 px-4 text-center',
        className,
      )}
    >
      <div className="font-display text-sm font-semibold text-foreground">{title}</div>
      <p className="mt-1 max-w-md text-xs text-muted-foreground">{body}</p>
    </div>
  );
}
