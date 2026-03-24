import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';

import { cn } from '@/lib/utils';

const badgeVariants = cva(
  'inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.2em] transition-colors',
  {
    variants: {
      variant: {
        default: 'border-primary/20 bg-primary/12 text-primary',
        secondary: 'border-border/70 bg-secondary/60 text-secondary-foreground',
        outline: 'border-border/80 bg-transparent text-muted-foreground',
        destructive: 'border-destructive/25 bg-destructive/12 text-destructive',
        success: 'border-accent/20 bg-accent/12 text-accent',
        warning: 'border-[hsl(43_96%_58%)]/25 bg-[hsl(43_96%_58%)]/12 text-[hsl(43_96%_58%)]',
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
