import type { ComponentType, ReactNode } from 'react';

import { Card, CardContent } from '@/components/ui/card';
import { cn } from '@/lib/utils';

interface WorkspaceMetricCardProps {
  label: ReactNode;
  value: ReactNode;
  hint: ReactNode;
  icon?: ComponentType<{ className?: string }>;
  className?: string;
  valueClassName?: string;
  iconClassName?: string;
}

export function WorkspaceMetricCard({
  label,
  value,
  hint,
  icon: Icon,
  className,
  valueClassName,
  iconClassName,
}: WorkspaceMetricCardProps) {
  return (
    <Card className={className}>
      <CardContent className="flex items-start justify-between gap-3 p-4">
        <div>
          <div className="text-[10px] font-semibold uppercase tracking-[0.22em] text-muted-foreground">{label}</div>
          <div className={cn('mt-1.5 font-display text-2xl font-semibold tracking-[-0.04em] text-foreground', valueClassName)}>
            {value}
          </div>
          <p className="mt-1 text-xs text-muted-foreground">{hint}</p>
        </div>
        {Icon ? (
          <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-border/70 bg-background/55 text-primary">
            <Icon className={cn('h-4 w-4', iconClassName)} />
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}
