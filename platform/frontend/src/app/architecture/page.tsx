"use client";

import { useEffect, useState } from "react";
import { MobileNav } from "@/components/shell/mobile-nav";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { fetchArchitecture } from "@/lib/api";

export default function ArchitecturePage() {
  const [data, setData] = useState<Awaited<ReturnType<typeof fetchArchitecture>> | null>(null);

  useEffect(() => {
    void fetchArchitecture().then(setData);
  }, []);

  return (
    <div className="space-y-6">
      <MobileNav />
      <header>
        <h1 className="text-3xl font-semibold tracking-tight text-white">System architecture</h1>
        <p className="mt-2 max-w-2xl text-sm text-zen-muted">
          A calm map of the offline pipeline — each stage emits audit entries for traceable decisions.
        </p>
      </header>

      <Card>
        <CardHeader>
          <CardTitle>{data?.title ?? "Pipeline"}</CardTitle>
          <CardDescription>Stages and data flow</CardDescription>
        </CardHeader>
        <CardContent className="space-y-8">
          <div className="relative flex flex-col gap-4 lg:flex-row lg:flex-wrap lg:justify-center">
            {data?.stages.map((s, idx) => (
              <div key={s.id} className="relative flex flex-1 min-w-[160px] flex-col items-center">
                <div className="w-full rounded-xl border border-white/10 bg-gradient-to-b from-white/10 to-white/[0.02] p-4 text-center shadow-glass backdrop-blur-xl">
                  <div className="text-[10px] font-semibold uppercase tracking-widest text-sky-200/80">
                    stage {idx + 1}
                  </div>
                  <div className="mt-2 text-sm font-semibold text-white">{s.label}</div>
                  <div className="mt-2 text-xs text-zen-muted">{s.description}</div>
                </div>
                {idx < (data?.stages.length ?? 0) - 1 ? (
                  <div className="hidden text-sky-400/50 lg:block lg:px-2">→</div>
                ) : null}
              </div>
            ))}
          </div>

          <div>
            <h3 className="text-sm font-medium text-slate-200">Edges (logical)</h3>
            <ul className="mt-2 grid gap-2 text-xs text-zen-muted md:grid-cols-2">
              {data?.edges.map(([a, b]) => (
                <li key={`${a}-${b}`} className="rounded-lg border border-white/5 bg-black/30 px-3 py-2 font-mono">
                  {a} → {b}
                </li>
              ))}
            </ul>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
