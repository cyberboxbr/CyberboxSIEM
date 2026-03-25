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
      <CardContent className="flex items-start justify-between gap-2 px-3 py-2.5">
        <div>
          <div className="text-[9px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">{label}</div>
          <div className={cn('mt-0.5 font-display text-lg font-semibold tracking-[-0.04em] text-foreground', valueClassName)}>
            {value}
          </div>
          <p className="mt-0.5 text-[10px] text-muted-foreground">{hint}</p>
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
