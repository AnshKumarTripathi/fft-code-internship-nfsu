import type { AnalystActionItem } from "@/lib/types";

export function anomalyDisposition(
  actions: AnalystActionItem[],
  anomalyId: string,
): "open" | "dismissed" {
  let status: "open" | "dismissed" = "open";
  for (const row of actions) {
    if (row.anomaly_id !== anomalyId) {
      continue;
    }
    if (row.action === "dismiss") {
      status = "dismissed";
    } else if (row.action === "reopen") {
      status = "open";
    }
  }
  return status;
}
