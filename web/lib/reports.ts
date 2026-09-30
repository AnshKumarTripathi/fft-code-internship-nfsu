import type { ReportFileItem } from "@/lib/types";

export function sanitizedIncidentId(incidentId: string): string {
  return incidentId.replace(/[^A-Za-z0-9_-]/g, "_");
}

export function isAiInsightFilename(filename: string): boolean {
  return /^incident_[A-Za-z0-9_-]+_ai_insight\.md$/i.test(filename);
}

export function isSafeReportFilename(filename: string): boolean {
  if (!filename || filename.includes("..") || filename.includes("/") || filename.includes("\\")) {
    return false;
  }
  return /^incident_[A-Za-z0-9_-]+(?:_ai_insight)?\.(md|html)$/i.test(filename);
}

export function htmlSiblingFilename(filename: string): string | null {
  if (!filename.endsWith(".md") || isAiInsightFilename(filename)) {
    return null;
  }
  return `${filename.slice(0, -3)}.html`;
}

export function incidentIdFromReportFilename(filename: string): string {
  let stem = filename.replace(/\.(md|html)$/i, "");
  if (stem.endsWith("_ai_insight")) {
    stem = stem.slice(0, -"_ai_insight".length);
  }
  return stem.startsWith("incident_") ? stem.slice("incident_".length) : stem;
}

export function insightFilenameForIncident(incidentId: string): string {
  return `incident_${sanitizedIncidentId(incidentId)}_ai_insight.md`;
}

export function reportsForIncident(
  items: ReportFileItem[],
  incidentId: string,
): ReportFileItem[] {
  const safe = sanitizedIncidentId(incidentId);
  const names = new Set([
    `incident_${safe}.md`,
    `incident_${safe}.html`,
    insightFilenameForIncident(incidentId),
  ]);
  return items.filter(
    (item) =>
      names.has(item.filename) ||
      item.incident_id === incidentId ||
      item.incident_id === safe,
  );
}
