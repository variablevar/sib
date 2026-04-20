"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { MobileNav } from "@/components/shell/mobile-nav";
import { SeverityChart } from "@/components/charts/severity-chart";
import { SeverityBadge } from "@/components/severity-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  fetchEvents,
  fetchResearchMetrics,
  fetchSummary,
  fetchTimeline,
  postDemoEmit,
  type EnrichedEvent,
  type SummaryStats,
} from "@/lib/api";

export default function OverviewPage() {
  const [summary, setSummary] = useState<SummaryStats | null>(null);
  const [timeline, setTimeline] = useState<Array<{ bucket: string; severity: string; count: number }>>([]);
  const [feed, setFeed] = useState<EnrichedEvent[]>([]);
  const [health, setHealth] = useState<Record<string, unknown> | null>(null);
  const [metrics, setMetrics] = useState<Awaited<ReturnType<typeof fetchResearchMetrics>> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [s, tl, ev, h, m] = await Promise.all([
        fetchSummary(),
        fetchTimeline(),
        fetchEvents(new URLSearchParams({ limit: "12" })),
        fetch("/api/v1/health").then((r) => r.json()),
        fetchResearchMetrics(),
      ]);
      setSummary(s);
      setTimeline(tl);
      setFeed(ev);
      setHealth(h);
      setMetrics(m);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load");
    }
  }, []);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 4000);
    return () => clearInterval(id);
  }, [refresh]);

  const emitDemo = async () => {
    setBusy(true);
    try {
      await postDemoEmit();
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Demo emit failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <MobileNav />
      <header className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <p className="text-xs uppercase tracking-[0.2em] text-sky-300/80">Zen Security Dashboard</p>
          <h1 className="mt-1 text-3xl font-semibold tracking-tight text-white">Overview</h1>
          <p className="mt-2 max-w-2xl text-sm text-zen-muted">
            Live posture from the local pipeline: Falco → Falcosidekick → normalization → rule engine → mock AI →
            SQLite. Polling keeps the feed calm and predictable without external brokers.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="accent" onClick={emitDemo} disabled={busy}>
            {busy ? "Emitting…" : "Emit demo event"}
          </Button>
          <Button variant="ghost" onClick={() => refresh()}>
            Refresh now
          </Button>
        </div>
      </header>

      {error ? (
        <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-100">
          {error}
        </div>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Event intensity</CardTitle>
            <CardDescription>Stacked counts by hour bucket and unified severity</CardDescription>
          </CardHeader>
          <CardContent>
            <SeverityChart data={timeline} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>System health</CardTitle>
            <CardDescription>Gateway + storage</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <div className="flex items-center justify-between">
              <span className="text-zen-muted">API</span>
              <span className="text-emerald-300">{String(health?.status || "…")}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-zen-muted">SQLite</span>
              <span className="text-emerald-300">
                {String((health?.components as Record<string, string> | undefined)?.sqlite || "…")}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-zen-muted">Total events</span>
              <span className="font-mono text-slate-100">{summary?.total_events ?? "—"}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-zen-muted">Labeled (research)</span>
              <span className="font-mono text-slate-100">{metrics?.labeled_count ?? 0}</span>
            </div>
            {metrics && metrics.labeled_count > 0 ? (
              <div className="rounded-lg border border-white/10 bg-black/30 p-3 text-xs text-zen-muted">
                Precision {metrics.precision?.toFixed(2) ?? "—"} · Recall {metrics.recall?.toFixed(2) ?? "—"} · FPR{" "}
                {metrics.false_positive_rate?.toFixed(2) ?? "—"}
              </div>
            ) : null}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-5">
        {(["critical", "high", "medium", "low", "info"] as const).map((s) => (
          <Card key={s} className="border-white/10">
            <CardHeader className="pb-2">
              <CardDescription className="capitalize">{s}</CardDescription>
              <CardTitle className="text-2xl font-semibold">
                {summary?.by_severity?.[s] ?? "—"}
              </CardTitle>
            </CardHeader>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle>Live event feed</CardTitle>
            <CardDescription>Most recent normalized records (poll every 4s)</CardDescription>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          {feed.length === 0 ? (
            <p className="text-sm text-zen-muted">No events yet — emit a demo or generate Falco traffic.</p>
          ) : (
            feed.map((e) => (
              <Link
                key={e.id}
                href={`/incidents/${e.id}`}
                className="flex flex-col gap-1 rounded-lg border border-white/5 bg-black/25 p-4 transition-colors hover:border-sky-400/30 hover:bg-black/40"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={e.core.severity} />
                  <span className="text-sm font-medium text-slate-100">{e.core.event_type}</span>
                  <span className="text-xs text-zen-muted">{new Date(e.core.timestamp).toLocaleString()}</span>
                </div>
                <p className="line-clamp-2 text-xs text-slate-400">{e.core.raw_log}</p>
              </Link>
            ))
          )}
        </CardContent>
      </Card>
    </div>
  );
}
