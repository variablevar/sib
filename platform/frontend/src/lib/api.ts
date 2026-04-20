const API_BASE = "";

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
    cache: "no-store",
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || res.statusText);
  }
  return res.json() as Promise<T>;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface EnrichedEvent {
  id: string;
  core: {
    timestamp: string;
    source: string;
    severity: Severity;
    event_type: string;
    container_id: string;
    raw_log: string;
  };
  rule_engine: {
    baseline_severity: Severity;
    matched_rules: string[];
    signals: Record<string, unknown>;
  };
  ai: {
    severity_score: number;
    explanation: string;
    confidence: number;
    /** Analyst-only guidance; no automated actions. */
    mitigations?: string[];
  };
  falco_priority: string;
  host: string;
  proc_name: string;
  evaluation?: {
    is_true_positive: boolean | null;
    notes: string;
  };
}

export interface SummaryStats {
  total_events: number;
  by_severity: Record<Severity, number>;
  last_event_at: string | null;
}

export function fetchSummary() {
  return apiFetch<SummaryStats>("/api/v1/stats/summary");
}

export function fetchEvents(params: URLSearchParams) {
  return apiFetch<EnrichedEvent[]>(`/api/v1/events?${params.toString()}`);
}

export function fetchEvent(id: string) {
  return apiFetch<EnrichedEvent>(`/api/v1/events/${encodeURIComponent(id)}`);
}

export function fetchTimeline() {
  return apiFetch<Array<{ bucket: string; severity: string; count: number }>>(
    "/api/v1/stats/timeline?limit_buckets=72",
  );
}

export function fetchRawLogs() {
  return apiFetch<Array<{ id: number; event_id: string | null; line: string; created_at: string }>>(
    "/api/v1/logs/raw?limit=200",
  );
}

export function fetchArchitecture() {
  return apiFetch<{
    title: string;
    stages: Array<{ id: string; label: string; description: string }>;
    edges: string[][];
  }>("/api/v1/architecture");
}

export function fetchResearchMetrics() {
  return apiFetch<{
    labeled_count: number;
    precision: number | null;
    recall: number | null;
    false_positive_rate: number | null;
  }>("/api/v1/research/metrics");
}

export function postDemoEmit() {
  return apiFetch<{ id: string; severity: string }>("/api/v1/demo/emit", {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export function postLabel(eventId: string, body: { is_true_positive: boolean | null; notes?: string }) {
  return apiFetch<{ status: string }>(`/api/v1/events/${encodeURIComponent(eventId)}/label`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}
