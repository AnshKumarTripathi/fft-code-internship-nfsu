/**
 * Phase 77 — central Docs deep-link map for in-UI help.
 * Missing keys fail closed to Docs home (never invent a 404 slug from UI chrome).
 * Self-contained (no local imports) so Node unit tests resolve without path aliases.
 */

const DETECTOR_DOC_SLUG: Record<string, string> = {
  statistical: "maths/statistical",
  spectral: "maths/spectral",
  ml: "maths/ml",
  cluster_outlier: "maths/cluster",
  changepoint: "maths/changepoint",
  seasonal: "maths/seasonal",
};

/** Keep in sync with DETECTOR_ORDER in detectors.ts (Phase 67). */
const REQUIRED_DETECTOR_IDS = [
  "statistical",
  "spectral",
  "ml",
  "cluster_outlier",
  "changepoint",
  "seasonal",
] as const;

export type DocsChartKind = "activity" | "psd" | "stft";
export type DocsKpiKind = "incidents" | "severity" | "detectors";

function docsHref(slug?: string): string {
  if (!slug) return "/docs";
  return `/docs/${slug}`;
}

/** Docs home — fail-closed target. */
export function docsHomeHref(): string {
  return docsHref();
}

export function docsDetectorHref(detectorId: string): string {
  const slug = DETECTOR_DOC_SLUG[detectorId];
  return slug ? docsHref(slug) : docsHomeHref();
}

export function docsWhyFlaggedHref(): string {
  return docsHref("workflows/why-flagged");
}

export function docsThresholdsHref(): string {
  return docsHref("maths/thresholds");
}

/** YAML knobs + raise/lower effects (Part E). */
export function docsConfigKnobsHref(): string {
  return docsHref("pipeline/config");
}

/** Large-corpus / 100 GB sharding how-to (Part E). */
export function docsLargeCorpusHref(): string {
  return docsHref("pipeline/large-corpus");
}

export function docsRobustZHref(): string {
  return docsHref("maths/robust-z");
}

export function docsChartsHref(kind?: DocsChartKind): string {
  const base = docsHref("navigate/charts");
  if (kind === "activity") return `${base}#activity-timeline`;
  if (kind === "psd") return `${base}#psd-welch-spectrum`;
  if (kind === "stft") return `${base}#stft-heatmap`;
  return base;
}

export function docsKpiHref(kind?: DocsKpiKind): string {
  const base = docsHref("reference/kpis");
  if (kind === "incidents" || kind === "severity" || kind === "detectors") {
    return `${base}#kpi-strip-meanings`;
  }
  return base;
}

export function docsPlaybooksHref(): string {
  return docsHref("reference/playbooks");
}

export function docsSnapshotsHref(): string {
  return docsHref("pipeline/snapshots");
}

export function docsContainersHref(): string {
  return docsHref("workflows/containers");
}

export function docsTroubleshootingHref(): string {
  return docsHref("reference/troubleshooting");
}

export function docsSingleWriterHref(): string {
  return docsHref("pipeline/single-writer");
}

/** Every Phase 67 glossary detector must map to a real maths chapter. */
export function docsDetectorMapComplete(): boolean {
  return REQUIRED_DETECTOR_IDS.every((id) => Boolean(DETECTOR_DOC_SLUG[id]));
}
