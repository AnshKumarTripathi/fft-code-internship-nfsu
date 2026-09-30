export const INCIDENT_PAGE_SIZE = 50;
export const ENTITY_PAGE_SIZE = 50;
export const RUN_PAGE_SIZE = 50;
export const REPORT_PAGE_SIZE = 50;
export const EVENT_PAGE_SIZE = 50;

export function parsePage(raw: string | undefined): number {
  const parsed = Number.parseInt(raw ?? "1", 10);
  if (!Number.isFinite(parsed) || parsed < 1) {
    return 1;
  }
  return parsed;
}

export const SEVERITIES = ["critical", "high", "medium", "low"] as const;

export const INCIDENT_DISPOSITIONS = ["open", "dismissed", "any"] as const;

export const INCIDENT_SORTS = [
  "severity",
  "start_time",
  "anomaly_count",
] as const;

/** Convert an ISO / query datetime into a value for ``datetime-local`` inputs. */
export function toDatetimeLocalValue(
  value: string | null | undefined,
): string {
  if (!value) {
    return "";
  }
  const normalized = value.trim().replace(/Z$/i, "").replace(/\+00:00$/, "");
  if (normalized.length >= 16) {
    return normalized.slice(0, 16);
  }
  return normalized;
}

export function displayValue(value: string | number | null | undefined): string {
  if (value === null || value === undefined || value === "") {
    return "—";
  }
  return String(value);
}

export function formatScore(score: number): string {
  return score.toFixed(1);
}

function pad2(value: number): string {
  return value < 10 ? `0${value}` : String(value);
}

/** Always render warehouse times as ISO-8601 UTC with a `Z` suffix. */
export function formatUtc(value: string | number | null | undefined): string {
  if (value === null || value === undefined || value === "") {
    return "—";
  }
  const raw = String(value);
  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) {
    if (
      /^\d{4}-\d{2}-\d{2}T/.test(raw) &&
      !/[zZ]|[+-]\d{2}:?\d{2}$/.test(raw)
    ) {
      return `${raw}Z`;
    }
    return raw;
  }
  return (
    `${parsed.getUTCFullYear()}-` +
    `${pad2(parsed.getUTCMonth() + 1)}-` +
    `${pad2(parsed.getUTCDate())}T` +
    `${pad2(parsed.getUTCHours())}:` +
    `${pad2(parsed.getUTCMinutes())}:` +
    `${pad2(parsed.getUTCSeconds())}Z`
  );
}

export function formatMaybeNumber(
  value: number | null | undefined,
  digits: number,
): string {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return "—";
  }
  return value.toFixed(digits);
}

export function runStatusBadgeClass(status: string): string {
  switch (status) {
    case "success":
      return "badge badge-success";
    case "error":
      return "badge badge-error";
    case "skipped":
      return "badge badge-ghost";
    default:
      return "badge";
  }
}

export function jobStageBadgeClass(status: string): string {
  switch (status) {
    case "success":
      return "badge badge-success";
    case "failed":
    case "error":
      return "badge badge-error";
    case "running":
      return "badge badge-info";
    case "skipped":
      return "badge badge-ghost";
    case "pending":
      return "badge badge-outline";
    default:
      return "badge";
  }
}

export function analysisStatusBadgeClass(status: string): string {
  switch (status) {
    case "ready":
      return "badge badge-success";
    case "failed":
      return "badge badge-error";
    case "running":
      return "badge badge-info";
    case "draft":
      return "badge badge-outline";
    default:
      return "badge";
  }
}

export function shortDigest(digest: string | null | undefined, chars = 8): string {
  if (!digest?.trim()) {
    return "—";
  }
  const value = digest.trim();
  if (value.length <= chars) {
    return value;
  }
  return `${value.slice(0, chars)}…`;
}

/** Truncate technical ids for secondary mono display (Phase 68 UUID demotion). */
export function shortId(id: string | null | undefined, chars = 8): string {
  return shortDigest(id, chars);
}

export function formatBytes(sizeBytes: number): string {
  if (!Number.isFinite(sizeBytes) || sizeBytes < 0) {
    return "—";
  }
  if (sizeBytes < 1024) {
    return `${sizeBytes} B`;
  }
  if (sizeBytes < 1024 * 1024) {
    return `${(sizeBytes / 1024).toFixed(1)} KiB`;
  }
  return `${(sizeBytes / (1024 * 1024)).toFixed(1)} MiB`;
}

export function isPipelineJobActive(status: string | null | undefined): boolean {
  return status === "queued" || status === "running" || status === "cancelling";
}

export function formatFields(
  fields: Record<string, unknown> | null | undefined,
): string {
  if (!fields) {
    return "—";
  }
  const entries = Object.entries(fields);
  if (entries.length === 0) {
    return "—";
  }
  return entries
    .map(([key, value]) => {
      if (value === null || value === undefined) {
        return `${key}=`;
      }
      if (typeof value === "object") {
        return `${key}=${JSON.stringify(value)}`;
      }
      return `${key}=${String(value)}`;
    })
    .join("; ");
}

export function severityBadgeClass(severity: string): string {
  switch (severity) {
    case "critical":
      return "badge badge-error";
    case "high":
      return "badge badge-warning";
    case "medium":
      return "badge badge-info";
    case "low":
      return "badge badge-ghost";
    default:
      return "badge";
  }
}

export function snippet(text: string | null | undefined, max = 120): string {
  if (!text) {
    return "—";
  }
  if (text.length <= max) {
    return text;
  }
  return `${text.slice(0, max)}…`;
}
