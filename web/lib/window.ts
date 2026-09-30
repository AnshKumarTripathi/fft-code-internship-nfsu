export const INCIDENT_CHART_PAD_HOURS = 6;
export const DEFAULT_ENTITY_PAD_HOURS = 6;

export function parsePadHours(
  raw: string | undefined,
  hasWindow: boolean,
): number {
  if (!hasWindow) {
    return 0;
  }
  if (raw === undefined || raw === "") {
    return DEFAULT_ENTITY_PAD_HOURS;
  }
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return DEFAULT_ENTITY_PAD_HOURS;
  }
  return parsed;
}

const MS_PER_HOUR = 60 * 60 * 1000;

function parseIso(value: string | null | undefined): Date | null {
  if (!value) {
    return null;
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return null;
  }
  return parsed;
}

export type EntityWindowQuery = {
  start?: string;
  end?: string;
  pad_hours?: string;
  order?: string;
};

export type EntityWindowState = {
  startParam?: string;
  endParam?: string;
  hasWindow: boolean;
  padHours: number;
  windowStart?: string;
  windowEnd?: string;
  order?: string;
  newestFirst: boolean;
};

export function resolveEntityWindow(
  query: EntityWindowQuery,
): EntityWindowState {
  const startParam = query.start?.trim() || undefined;
  const endParam = query.end?.trim() || undefined;
  const hasWindow = Boolean(startParam || endParam);
  const padHours = parsePadHours(query.pad_hours, hasWindow);
  const padded = hasWindow
    ? padIncidentWindow(startParam, endParam, padHours)
    : {};
  const order = query.order?.trim() || undefined;
  return {
    startParam,
    endParam,
    hasWindow,
    padHours,
    windowStart: padded.start,
    windowEnd: padded.end,
    order,
    newestFirst: !hasWindow && order !== "oldest",
  };
}

export function padIncidentWindow(
  start: string | null | undefined,
  end: string | null | undefined,
  padHours: number = INCIDENT_CHART_PAD_HOURS,
): { start?: string; end?: string } {
  const delta = padHours * MS_PER_HOUR;
  const startDate = parseIso(start);
  const endDate = parseIso(end);
  return {
    start: startDate
      ? new Date(startDate.getTime() - delta).toISOString()
      : undefined,
    end: endDate
      ? new Date(endDate.getTime() + delta).toISOString()
      : undefined,
  };
}
