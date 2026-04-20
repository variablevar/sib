import * as React from "react";
import { cn } from "@/lib/utils";

export type SelectProps = React.SelectHTMLAttributes<HTMLSelectElement>;

const Select = React.forwardRef<HTMLSelectElement, SelectProps>(({ className, children, ...props }, ref) => (
  <select
    className={cn(
      "flex h-9 w-full rounded-md border border-white/10 bg-black/30 px-2 text-sm text-slate-100 backdrop-blur focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400/30",
      className,
    )}
    ref={ref}
    {...props}
  >
    {children}
  </select>
));
Select.displayName = "Select";

export { Select };
