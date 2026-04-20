"use client";

import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { Severity } from "@/lib/api";

type Row = { bucket: string; severity: string; count: number };

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

const colors: Record<Severity, string> = {
  critical: "#fb7185",
  high: "#fb923c",
  medium: "#fbbf24",
  low: "#38bdf8",
  info: "#94a3b8",
};

function pivot(rows: Row[]) {
  const map = new Map<string, Record<string, number>>();
  for (const r of rows) {
    const key = r.bucket;
    if (!map.has(key)) {
      const base: Record<string, number | string> = { bucket: key };
      for (const s of SEVERITIES) base[s] = 0;
      map.set(key, base as Record<string, number>);
    }
    const entry = map.get(key)!;
    const sev = r.severity as Severity;
    if (SEVERITIES.includes(sev)) {
      entry[sev] = (entry[sev] || 0) + r.count;
    }
  }
  return Array.from(map.values()).sort((a, b) => String(a.bucket).localeCompare(String(b.bucket)));
}

export function SeverityChart({ data }: { data: Row[] }) {
  const chartData = pivot(data);
  return (
    <div className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={chartData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
          <defs>
            {SEVERITIES.map((s) => (
              <linearGradient key={s} id={`fill-${s}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={colors[s]} stopOpacity={0.35} />
                <stop offset="95%" stopColor={colors[s]} stopOpacity={0} />
              </linearGradient>
            ))}
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.12)" vertical={false} />
          <XAxis dataKey="bucket" tick={{ fill: "#94a3b8", fontSize: 10 }} axisLine={false} tickLine={false} />
          <YAxis tick={{ fill: "#94a3b8", fontSize: 10 }} axisLine={false} tickLine={false} />
          <Tooltip
            contentStyle={{
              background: "rgba(10,12,20,0.92)",
              border: "1px solid rgba(148,163,184,0.15)",
              borderRadius: 8,
              fontSize: 12,
            }}
          />
          {SEVERITIES.map((s) => (
            <Area
              key={s}
              type="monotone"
              dataKey={s}
              stackId="1"
              stroke={colors[s]}
              fill={`url(#fill-${s})`}
              strokeWidth={1}
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
