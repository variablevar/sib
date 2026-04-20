import type { Severity } from "@/lib/api";
import { Badge } from "@/components/ui/badge";

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  const v = severity as Severity;
  if (v === "critical" || v === "high" || v === "medium" || v === "low" || v === "info") {
    return <Badge variant={v}>{severity}</Badge>;
  }
  return <Badge variant="info">{severity}</Badge>;
}
