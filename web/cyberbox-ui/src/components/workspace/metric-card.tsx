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
      <CardContent className="flex items-start justify-between gap-4 p-5">
        <div>
          <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">{label}</div>
          <div className={cn('mt-3 font-display text-3xl font-semibold tracking-[-0.04em] text-foreground', valueClassName)}>
            {value}
          </div>
          <p className="mt-2 text-sm text-muted-foreground">{hint}</p>
        </div>
        {Icon ? (
          <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-border/70 bg-background/55 text-primary">
            <Icon className={cn('h-5 w-5', iconClassName)} />
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}
