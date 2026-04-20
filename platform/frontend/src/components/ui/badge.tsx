import type { HTMLAttributes } from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium transition-colors",
  {
    variants: {
      variant: {
        critical: "border-rose-500/40 bg-rose-500/15 text-rose-100",
        high: "border-orange-400/40 bg-orange-400/15 text-orange-100",
        medium: "border-amber-300/40 bg-amber-300/15 text-amber-50",
        low: "border-sky-400/40 bg-sky-400/15 text-sky-50",
        info: "border-slate-500/40 bg-slate-500/15 text-slate-200",
      },
    },
    defaultVariants: { variant: "info" },
  },
);

export interface BadgeProps extends HTMLAttributes<HTMLDivElement>, VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />;
}
