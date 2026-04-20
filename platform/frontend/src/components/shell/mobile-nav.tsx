"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";

const links = [
  { href: "/", label: "Home" },
  { href: "/explorer", label: "Explorer" },
  { href: "/architecture", label: "Arch" },
  { href: "/logs", label: "Logs" },
];

export function MobileNav() {
  const pathname = usePathname();
  return (
    <div className="mb-6 flex gap-2 overflow-x-auto rounded-xl border border-white/10 bg-black/30 p-2 lg:hidden">
      {links.map((l) => (
        <Link
          key={l.href}
          href={l.href}
          className={cn(
            "whitespace-nowrap rounded-md px-3 py-1.5 text-xs",
            pathname === l.href ? "bg-white/15 text-white" : "text-slate-400",
          )}
        >
          {l.label}
        </Link>
      ))}
    </div>
  );
}
