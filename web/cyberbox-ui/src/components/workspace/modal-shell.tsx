import type { ReactNode } from 'react';
import { XCircle } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { cn } from '@/lib/utils';

interface WorkspaceModalProps {
  open: boolean;
  title: ReactNode;
  description?: ReactNode;
  children: ReactNode;
  onClose: () => void;
  panelClassName?: string;
  contentClassName?: string;
}

export function WorkspaceModal({
  open,
  title,
  description,
  children,
  onClose,
  panelClassName,
  contentClassName,
}: WorkspaceModalProps) {
  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-[80] flex items-center justify-center bg-slate-950/70 px-4 py-8 backdrop-blur-sm"
      onClick={onClose}
    >
      <Card
        className={cn('w-full border-border/80 bg-popover/95 shadow-shell', panelClassName)}
        onClick={(event) => event.stopPropagation()}
      >
        <CardHeader className="pb-4">
          <div className="flex items-start justify-between gap-4">
            <div>
              <CardTitle>{title}</CardTitle>
              {description ? <CardDescription className="mt-2">{description}</CardDescription> : null}
            </div>
            <Button type="button" variant="ghost" size="icon" className="h-10 w-10 rounded-2xl" onClick={onClose}>
              <XCircle className="h-4 w-4" />
            </Button>
          </div>
        </CardHeader>
        <CardContent className={cn('space-y-5', contentClassName)}>{children}</CardContent>
      </Card>
    </div>
  );
}
