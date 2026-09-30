function withQuery(
  path: string,
  params: Record<string, string | number | null | undefined>,
): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") {
      continue;
    }
    if (key === "page" && Number(value) <= 1) {
      continue;
    }
    if (key === "pad_hours" && Number(value) <= 0) {
      continue;
    }
    if (key === "step" && value === "timeline") {
      continue;
    }
    search.set(key, String(value));
  }
  const qs = search.toString();
  return qs ? `${path}?${qs}` : path;
}

function entityWindowParams(
  start?: string | null,
  end?: string | null,
  padHours?: number | null,
): Record<string, string | number | null | undefined> {
  return {
    start: start ?? undefined,
    end: end ?? undefined,
    pad_hours: padHours ?? undefined,
  };
}

export function entityHref(
  entityId: string,
  start?: string | null,
  end?: string | null,
  padHours?: number | null,
): string {
  return withQuery(
    `/entities/${encodeURIComponent(entityId)}`,
    entityWindowParams(start, end, padHours),
  );
}

export function entityAnalysisHref(
  entityId: string,
  start?: string | null,
  end?: string | null,
  padHours?: number | null,
): string {
  return withQuery(
    `/entities/${encodeURIComponent(entityId)}/analysis`,
    entityWindowParams(start, end, padHours),
  );
}

export function entityEventsHref(
  entityId: string,
  start?: string | null,
  end?: string | null,
  padHours?: number | null,
  page?: number,
): string {
  return withQuery(`/entities/${encodeURIComponent(entityId)}/events`, {
    ...entityWindowParams(start, end, padHours),
    page,
  });
}

export function incidentHref(incidentId: string): string {
  return `/incidents/${encodeURIComponent(incidentId)}`;
}

export function incidentAnalysisHref(incidentId: string): string {
  return `/incidents/${encodeURIComponent(incidentId)}/analysis`;
}

export function incidentEventsHref(
  incidentId: string,
  page?: number,
  step?: "timeline" | "edges",
): string {
  return withQuery(`/incidents/${encodeURIComponent(incidentId)}/events`, {
    step,
    page,
  });
}

export function entityListHref(q?: string, page?: number): string {
  const search = new URLSearchParams();
  if (q) {
    search.set("q", q);
  }
  if (page && page > 1) {
    search.set("page", String(page));
  }
  const qs = search.toString();
  return qs ? `/entities?${qs}` : "/entities";
}

export type IncidentListHrefParams = {
  severity?: string;
  entity_id?: string;
  q?: string;
  start_after?: string;
  end_before?: string;
  detector?: string;
  min_detectors?: number | string;
  disposition?: string;
  sort?: string;
  order?: string;
  page?: number;
};

function appendIncidentListParams(
  search: URLSearchParams,
  params: IncidentListHrefParams,
): void {
  if (params.severity) {
    search.set("severity", params.severity);
  }
  if (params.entity_id) {
    search.set("entity_id", params.entity_id);
  }
  if (params.q) {
    search.set("q", params.q);
  }
  if (params.start_after) {
    search.set("start_after", params.start_after);
  }
  if (params.end_before) {
    search.set("end_before", params.end_before);
  }
  if (params.detector) {
    search.set("detector", params.detector);
  }
  if (
    params.min_detectors !== undefined &&
    params.min_detectors !== null &&
    String(params.min_detectors) !== "" &&
    Number(params.min_detectors) >= 1
  ) {
    search.set("min_detectors", String(params.min_detectors));
  }
  if (params.disposition) {
    search.set("disposition", params.disposition);
  }
  if (params.sort && params.sort !== "severity") {
    search.set("sort", params.sort);
  }
  if (params.order === "asc") {
    search.set("order", "asc");
  }
  if (params.page && params.page > 1) {
    search.set("page", String(params.page));
  }
}

export function incidentListHref(params: IncidentListHrefParams): string {
  const search = new URLSearchParams();
  appendIncidentListParams(search, params);
  const qs = search.toString();
  return qs ? `/incidents?${qs}` : "/incidents";
}

export function runsHref(page?: number): string {
  if (!page || page <= 1) {
    return "/runs";
  }
  return `/runs?page=${page}`;
}

export function pipelineHref(): string {
  return "/";
}

export function analysisTriageHref(
  analysisId: string,
  params: IncidentListHrefParams = {},
): string {
  const search = new URLSearchParams();
  appendIncidentListParams(search, params);
  const qs = search.toString();
  const base = `/analyses/${encodeURIComponent(analysisId)}`;
  return qs ? `${base}?${qs}` : base;
}

export function reportsHref(page?: number): string {
  if (!page || page <= 1) {
    return "/reports";
  }
  return `/reports?page=${page}`;
}

export function reportHref(filename: string): string {
  return `/reports/${encodeURIComponent(filename)}`;
}

export function htmlReportHref(incidentId: string): string {
  const safe = incidentId.replace(/[^A-Za-z0-9_-]/g, "_");
  return reportHref(`incident_${safe}.html`);
}
