import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';

import { cn } from '@/lib/utils';

const badgeVariants = cva(
  'inline-flex items-center rounded-full border px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.24em] transition-colors',
  {
    variants: {
      variant: {
        default: 'border-primary/20 bg-primary/12 text-primary',
        secondary: 'border-border/70 bg-secondary/60 text-secondary-foreground',
        outline: 'border-border/80 bg-transparent text-muted-foreground',
        destructive: 'border-destructive/25 bg-destructive/12 text-destructive',
        success: 'border-primary/20 bg-primary/12 text-primary',
        warning: 'border-accent/25 bg-accent/15 text-accent-foreground',
        info: 'border-chart-2/20 bg-chart-2/12 text-chart-2',
      },
    },
    defaultVariants: {
      variant: 'default',
    },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />;
}

export { Badge, badgeVariants };
