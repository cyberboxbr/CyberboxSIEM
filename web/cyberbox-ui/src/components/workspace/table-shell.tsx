import type { ReactNode } from 'react';

import { cn } from '@/lib/utils';

interface WorkspaceTableShellProps {
  children: ReactNode;
  className?: string;
}

export function WorkspaceTableShell({ children, className }: WorkspaceTableShellProps) {
  return (
    <div className={cn('overflow-x-auto rounded-lg border border-border/70 bg-background/35', className)}>
      {children}
    </div>
  );
}
