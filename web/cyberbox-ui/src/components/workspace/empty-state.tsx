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
        'flex min-h-[260px] flex-col items-center justify-center rounded-[24px] border border-dashed border-border/80 bg-background/30 px-6 text-center',
        className,
      )}
    >
      <div className="font-display text-lg font-semibold text-foreground">{title}</div>
      <p className="mt-2 max-w-md text-sm text-muted-foreground">{body}</p>
    </div>
  );
}
