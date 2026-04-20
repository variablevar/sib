"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { MobileNav } from "@/components/shell/mobile-nav";
import { SeverityBadge } from "@/components/severity-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { fetchEvent, postLabel, type EnrichedEvent } from "@/lib/api";

export default function IncidentPage() {
  const params = useParams<{ id: string }>();
  const id = params?.id;
  const [ev, setEv] = useState<EnrichedEvent | null>(null);
  const [notes, setNotes] = useState("");
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!id) return;
    try {
      setEv(await fetchEvent(id));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Not found");
    }
  }, [id]);

  useEffect(() => {
    void load();
  }, [load]);

  const label = async (isTp: boolean | null) => {
    if (!id) return;
    await postLabel(id, { is_true_positive: isTp, notes });
    await load();
  };

  if (!id) return null;

  return (
    <div className="space-y-6">
      <MobileNav />
      <div className="flex items-center gap-3 text-sm text-zen-muted">
        <Link href="/explorer" className="text-sky-300 hover:underline">
          ← Back to explorer
        </Link>
      </div>

      {error ? (
        <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-100">
          {error}
        </div>
      ) : null}

      {ev ? (
        <>
          <header className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={ev.core.severity} />
                <h1 className="text-2xl font-semibold text-white">{ev.core.event_type}</h1>
              </div>
              <p className="mt-1 font-mono text-xs text-slate-500">{ev.id}</p>
            </div>
            <div className="text-xs text-zen-muted">
              <div>Host: {ev.host || "—"}</div>
              <div>Process: {ev.proc_name || "—"}</div>
              <div>Falco priority: {ev.falco_priority || "—"}</div>
            </div>
          </header>

          <div className="grid gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Core event</CardTitle>
                <CardDescription>Unified schema fields</CardDescription>
              </CardHeader>
              <CardContent className="space-y-2 text-sm">
                <Row k="timestamp" v={ev.core.timestamp} />
                <Row k="source" v={ev.core.source} />
                <Row k="severity" v={ev.core.severity} />
                <Row k="event_type" v={ev.core.event_type} />
                <Row k="container_id" v={ev.core.container_id || "—"} />
                <div>
                  <div className="text-xs uppercase text-zen-muted">raw_log</div>
                  <pre className="mt-1 whitespace-pre-wrap rounded-lg border border-white/10 bg-black/40 p-3 text-xs text-slate-200">
                    {ev.core.raw_log}
                  </pre>
                </div>
              </CardContent>
            </Card>

            <Card className="border-violet-400/20">
              <CardHeader>
                <CardTitle>Mock AI panel</CardTitle>
                <CardDescription>Pluggable engine — heuristic baseline for dissertation extensions</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3 text-sm">
                <div className="flex items-center justify-between">
                  <span className="text-zen-muted">Severity score</span>
                  <span className="font-mono text-lg text-white">{ev.ai.severity_score}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-zen-muted">Confidence</span>
                  <span className="font-mono text-white">{ev.ai.confidence}</span>
                </div>
                <div>
                  <div className="text-xs uppercase text-zen-muted">Explanation</div>
                  <p className="mt-2 leading-relaxed text-slate-200">{ev.ai.explanation}</p>
                </div>
                {(ev.ai.mitigations?.length ?? 0) > 0 ? (
                  <div>
                    <div className="text-xs uppercase text-zen-muted">Suggested analyst actions</div>
                    <p className="mt-1 text-[11px] leading-relaxed text-slate-500">
                      Decision support only — your team validates and executes; nothing is auto-enforced.
                    </p>
                    <ul className="mt-2 list-disc space-y-1.5 pl-5 text-slate-200">
                      {ev.ai.mitigations!.map((m, i) => (
                        <li key={i}>{m}</li>
                      ))}
                    </ul>
                  </div>
                ) : null}
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Rule engine output</CardTitle>
              <CardDescription>Deterministic baseline for comparison with AI / future LLM</CardDescription>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              <Row k="baseline_severity" v={ev.rule_engine.baseline_severity} />
              <div>
                <div className="text-xs uppercase text-zen-muted">matched_rules</div>
                <ul className="mt-1 list-disc pl-5 text-slate-300">
                  {ev.rule_engine.matched_rules.map((m) => (
                    <li key={m}>{m}</li>
                  ))}
                </ul>
              </div>
              <pre className="mt-2 overflow-x-auto rounded-lg border border-white/10 bg-black/40 p-3 text-xs text-slate-300">
                {JSON.stringify(ev.rule_engine.signals, null, 2)}
              </pre>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Evaluation labels</CardTitle>
              <CardDescription>Ground truth for precision / recall / false positive studies</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="text-sm text-slate-300">
                Current:{" "}
                {!ev.evaluation || ev.evaluation.is_true_positive === null
                  ? "unlabeled"
                  : ev.evaluation.is_true_positive
                    ? "true positive"
                    : "false positive"}
              </div>
              <Input placeholder="Analyst notes" value={notes} onChange={(e) => setNotes(e.target.value)} />
              <div className="flex flex-wrap gap-2">
                <Button variant="accent" onClick={() => label(true)}>
                  Mark true positive
                </Button>
                <Button variant="default" onClick={() => label(false)}>
                  Mark false positive
                </Button>
                <Button variant="ghost" onClick={() => label(null)}>
                  Clear label
                </Button>
              </div>
            </CardContent>
          </Card>
        </>
      ) : (
        !error && <p className="text-sm text-zen-muted">Loading…</p>
      )}
    </div>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex gap-3">
      <div className="w-32 shrink-0 text-xs uppercase text-zen-muted">{k}</div>
      <div className="text-slate-100">{v}</div>
    </div>
  );
}
