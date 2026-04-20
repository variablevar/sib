"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { MobileNav } from "@/components/shell/mobile-nav";
import { SeverityBadge } from "@/components/severity-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { fetchEvents, type EnrichedEvent, type Severity } from "@/lib/api";

const severities: Array<Severity | ""> = ["", "critical", "high", "medium", "low", "info"];

export default function ExplorerPage() {
  const [rows, setRows] = useState<EnrichedEvent[]>([]);
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState<Severity | "">("");
  const [container, setContainer] = useState("");
  const [loading, setLoading] = useState(false);

  const params = useMemo(() => {
    const p = new URLSearchParams({ limit: "100" });
    if (q) p.set("q", q);
    if (severity) p.set("severity", severity);
    if (container) p.set("container", container);
    return p;
  }, [q, severity, container]);

  const load = async () => {
    setLoading(true);
    try {
      setRows(await fetchEvents(params));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="space-y-6">
      <MobileNav />
      <header>
        <h1 className="text-3xl font-semibold tracking-tight text-white">Threat Explorer</h1>
        <p className="mt-2 max-w-2xl text-sm text-zen-muted">
          Searchable grid across severity, container, and free text. All queries hit the local SQLite index.
        </p>
      </header>

      <Card>
        <CardHeader>
          <CardTitle>Filters</CardTitle>
          <CardDescription>Compose filters then apply — keeps queries explicit for reproducible research.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 md:grid-cols-4">
          <Input placeholder="Search text (rule / log)" value={q} onChange={(e) => setQ(e.target.value)} />
          <Select value={severity} onChange={(e) => setSeverity(e.target.value as Severity | "")}>
            <option value="">Any severity</option>
            {severities
              .filter(Boolean)
              .map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
          </Select>
          <Input placeholder="Container id contains…" value={container} onChange={(e) => setContainer(e.target.value)} />
          <Button variant="accent" onClick={() => load()} disabled={loading}>
            {loading ? "Loading…" : "Apply"}
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Events</CardTitle>
          <CardDescription>{rows.length} results</CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          <table className="w-full min-w-[720px] border-collapse text-left text-sm">
            <thead className="text-xs uppercase text-zen-muted">
              <tr className="border-b border-white/10">
                <th className="py-2 pr-3">Severity</th>
                <th className="py-2 pr-3">Type</th>
                <th className="py-2 pr-3">Container</th>
                <th className="py-2 pr-3">Time</th>
                <th className="py-2 pr-3">AI score</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((e) => (
                <tr key={e.id} className="border-b border-white/5 hover:bg-white/[0.03]">
                  <td className="py-3 pr-3">
                    <SeverityBadge severity={e.core.severity} />
                  </td>
                  <td className="py-3 pr-3">
                    <Link className="text-sky-300 hover:underline" href={`/incidents/${e.id}`}>
                      {e.core.event_type}
                    </Link>
                  </td>
                  <td className="max-w-[200px] truncate py-3 pr-3 font-mono text-xs text-slate-400">
                    {e.core.container_id || "—"}
                  </td>
                  <td className="py-3 pr-3 text-xs text-slate-400">{new Date(e.core.timestamp).toLocaleString()}</td>
                  <td className="py-3 pr-3 font-mono text-xs">{e.ai.severity_score}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  );
}
