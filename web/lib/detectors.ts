export const DETECTOR_ORDER = [
  "statistical",
  "spectral",
  "ml",
  "cluster_outlier",
  "changepoint",
  "seasonal",
] as const;

export const DETECTOR_ROLES: Record<string, string> = {
  statistical: "rate",
  spectral: "rhythm",
  ml: "sequence",
  cluster_outlier: "peer-outlier",
  changepoint: "level-shift",
  seasonal: "seasonal-residual",
};

export const DETECTOR_LABELS: Record<string, string> = {
  statistical: "statistical",
  spectral: "spectral",
  ml: "ml",
  cluster_outlier: "cluster",
  changepoint: "changepoint",
  seasonal: "seasonal",
};

/** Phase 67 — one-line mentor meanings (no SDD required). */
export const DETECTOR_MEANINGS: Record<string, string> = {
  statistical: "Volume unusually high vs this entity’s typical windows",
  spectral: "Daily/periodic shape or energy changed",
  ml: "Template/bigram mix unusual vs this batch",
  cluster_outlier: "Unlike peer groups in the lab",
  changepoint: "Sustained step up/down in volume",
  seasonal: "Off this entity’s usual time-of-day profile",
};

export const CHART_CAPTIONS = {
  activity:
    "How busy this entity was over time. Shaded bands mark windows detectors flagged.",
  psd: "Typical rhythm fingerprint for this entity—peaks are recurring periods (hours), not attack signatures.",
  stft: "How that rhythm changes across the selected window—brighter means more power at that period and time.",
} as const;

export const KPI_MEANINGS = {
  incidents: "Correlated flags needing review (warehouse- or snapshot-wide).",
  severity: "How serious the correlated incident looks—not a statistical p-value.",
  detectors: "Which detection family contributed. Roles below explain each family.",
} as const;

export type DetectorGlossaryEntry = {
  id: string;
  role: string;
  meaning: string;
  label: string;
};

export function detectorRole(name: string): string {
  return DETECTOR_ROLES[name] ?? name;
}

export function detectorLabel(name: string): string {
  return DETECTOR_LABELS[name] ?? name;
}

export function detectorMeaning(name: string): string {
  return DETECTOR_MEANINGS[name] ?? "";
}

export function detectorTeaser(name: string): string {
  const role = detectorRole(name);
  const meaning = detectorMeaning(name);
  return meaning ? `${role}: ${meaning}` : role;
}

/** First detector teaser for an incident list row. */
export function incidentDetectorTeaser(detectorSet: string[] | undefined): string {
  const first = detectorSet?.[0];
  if (!first) {
    return "No detector tags on this row.";
  }
  return detectorTeaser(first);
}

export function detectorGlossary(): DetectorGlossaryEntry[] {
  return DETECTOR_ORDER.map((id) => ({
    id,
    role: detectorRole(id),
    meaning: detectorMeaning(id),
    label: detectorLabel(id),
  }));
}
