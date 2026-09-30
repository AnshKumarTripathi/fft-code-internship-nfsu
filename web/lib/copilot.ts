/** Client + server shared copilot helpers (Phase 97). Self-contained for Node tests. */

export const MAX_ATTACHMENT_CHARS = 4000;

const COPILOT_PANEL_SIZE_KEY = "fft-copilot-panel-size";

export type CopilotPanelSize = {
  width: number;
  height: number;
};

export const COPILOT_PANEL_MIN_WIDTH = 280;
export const COPILOT_PANEL_MIN_HEIGHT = 320;
export const COPILOT_PANEL_DEFAULT_WIDTH = 384;
export const COPILOT_PANEL_DEFAULT_HEIGHT = 512;

function incidentIdFromReportFilename(filename: string): string {
  let stem = filename.replace(/\.(md|html)$/i, "");
  if (stem.endsWith("_ai_insight")) {
    stem = stem.slice(0, -"_ai_insight".length);
  }
  return stem.startsWith("incident_") ? stem.slice("incident_".length) : stem;
}

/** Resolve incident id from /incidents/[id] or /reports/incident_*.md|.html */
export function incidentIdFromPath(pathname: string): string | null {
  const path = (pathname || "").trim();
  if (!path) {
    return null;
  }

  const incidentMatch = path.match(/^\/incidents\/([^/]+)/);
  if (incidentMatch?.[1]) {
    return decodeURIComponent(incidentMatch[1]);
  }

  const reportMatch = path.match(
    /^\/reports\/(incident_[A-Za-z0-9_-]+(?:_ai_insight)?\.(?:md|html))$/i,
  );
  if (reportMatch?.[1]) {
    const id = incidentIdFromReportFilename(decodeURIComponent(reportMatch[1]));
    return id || null;
  }

  return null;
}

/** Bare report filename from /reports/... when present. */
export function reportFilenameFromPath(pathname: string): string | null {
  const match = (pathname || "").match(
    /^\/reports\/(incident_[A-Za-z0-9_-]+(?:_ai_insight)?\.(?:md|html))$/i,
  );
  return match?.[1] ? decodeURIComponent(match[1]) : null;
}

/** Entity id from /entities/[id] (not the index /entities). */
export function entityIdFromPath(pathname: string): string | null {
  const match = (pathname || "").match(/^\/entities\/([^/]+)/);
  if (!match?.[1]) {
    return null;
  }
  return decodeURIComponent(match[1]);
}

/** True when the operator is on the Entities registry or an entity detail page. */
export function isEntitiesRoute(pathname: string): boolean {
  const path = (pathname || "").trim();
  return path === "/entities" || path.startsWith("/entities/");
}

export function loadCopilotPanelSize(): CopilotPanelSize {
  if (typeof window === "undefined") {
    return {
      width: COPILOT_PANEL_DEFAULT_WIDTH,
      height: COPILOT_PANEL_DEFAULT_HEIGHT,
    };
  }
  try {
    const raw = window.localStorage.getItem(COPILOT_PANEL_SIZE_KEY);
    if (!raw) {
      return {
        width: COPILOT_PANEL_DEFAULT_WIDTH,
        height: COPILOT_PANEL_DEFAULT_HEIGHT,
      };
    }
    const parsed = JSON.parse(raw) as Partial<CopilotPanelSize>;
    return clampCopilotPanelSize({
      width: Number(parsed.width) || COPILOT_PANEL_DEFAULT_WIDTH,
      height: Number(parsed.height) || COPILOT_PANEL_DEFAULT_HEIGHT,
    });
  } catch {
    return {
      width: COPILOT_PANEL_DEFAULT_WIDTH,
      height: COPILOT_PANEL_DEFAULT_HEIGHT,
    };
  }
}

export function saveCopilotPanelSize(size: CopilotPanelSize): void {
  if (typeof window === "undefined") {
    return;
  }
  try {
    window.localStorage.setItem(
      COPILOT_PANEL_SIZE_KEY,
      JSON.stringify(clampCopilotPanelSize(size)),
    );
  } catch {
    // ignore quota / private mode
  }
}

export function clampCopilotPanelSize(size: CopilotPanelSize): CopilotPanelSize {
  const maxWidth =
    typeof window === "undefined"
      ? 720
      : Math.max(COPILOT_PANEL_MIN_WIDTH, window.innerWidth - 40);
  const maxHeight =
    typeof window === "undefined"
      ? 800
      : Math.max(COPILOT_PANEL_MIN_HEIGHT, window.innerHeight - 120);
  return {
    width: Math.min(maxWidth, Math.max(COPILOT_PANEL_MIN_WIDTH, Math.round(size.width))),
    height: Math.min(
      maxHeight,
      Math.max(COPILOT_PANEL_MIN_HEIGHT, Math.round(size.height)),
    ),
  };
}
