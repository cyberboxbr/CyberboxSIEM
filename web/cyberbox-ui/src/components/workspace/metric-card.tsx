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
      <CardContent className="flex flex-col items-center justify-center px-3 py-2.5 text-center">
        <div className="text-[9px] font-semibold uppercase tracking-[0.22em] text-muted-foreground">{label}</div>
        <div className={cn('mt-1 font-display text-xl font-semibold tracking-[-0.04em] text-foreground', valueClassName)}>
          {value}
        </div>
        <p className="mt-0.5 text-[10px] text-muted-foreground">{hint}</p>
      </CardContent>
    </Card>
  );
}
