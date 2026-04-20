"use client";

import type { ReactNode } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Activity, Binary, LayoutDashboard, Network, ScrollText } from "lucide-react";
import { cn } from "@/lib/utils";

const links = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/explorer", label: "Threat Explorer", icon: Activity },
  { href: "/architecture", label: "Architecture", icon: Network },
  { href: "/logs", label: "Logs", icon: ScrollText },
];

export function ZenShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();

  return (
    <div className="min-h-screen bg-zen-gradient text-slate-100">
      <div className="mx-auto flex max-w-[1400px] gap-6 px-4 py-8 lg:px-8">
        <aside className="hidden w-56 shrink-0 flex-col gap-2 lg:flex">
          <div className="mb-6 flex items-center gap-2 px-2">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-white/10 bg-white/5 shadow-glass">
              <Binary className="h-5 w-5 text-sky-300" />
            </div>
            <div>
              <div className="text-sm font-semibold tracking-tight">ACSP</div>
              <div className="text-[11px] text-zen-muted">Zen Security</div>
            </div>
          </div>
          <nav className="flex flex-col gap-1">
            {links.map(({ href, label, icon: Icon }) => {
              const active = pathname === href;
              return (
                <Link
                  key={href}
                  href={href}
                  className={cn(
                    "flex items-center gap-2 rounded-lg px-3 py-2 text-sm transition-colors",
                    active
                      ? "border border-white/10 bg-white/10 text-white"
                      : "text-slate-300 hover:bg-white/5 hover:text-white",
                  )}
                >
                  <Icon className="h-4 w-4 opacity-80" />
                  {label}
                </Link>
              );
            })}
          </nav>
          <div className="mt-auto rounded-lg border border-white/10 bg-black/20 p-3 text-[11px] leading-relaxed text-zen-muted">
            Fully local stack — no external AI APIs. Mock engine uses heuristics for research baselines.
          </div>
        </aside>
        <main className="min-w-0 flex-1">{children}</main>
      </div>
      <div className="fixed bottom-0 left-0 right-0 border-t border-white/5 bg-black/40 px-4 py-2 text-center text-[11px] text-slate-500 backdrop-blur lg:hidden">
        Open on a larger screen for the full navigation, or use the top bar in each page.
      </div>
    </div>
  );
}
