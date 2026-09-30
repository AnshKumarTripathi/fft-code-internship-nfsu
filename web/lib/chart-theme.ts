/** Lab Paper chart colors — mirrors CSS vars in globals.css for Chart.js. */

export type ChartTheme = {
  ink: string;
  grid: string;
  tick: string;
  series: string;
  flagStatistical: string;
  flagSpectral: string;
  fontSans: string;
  fontMono: string;
};

const FALLBACK: ChartTheme = {
  ink: "oklch(26% 0.025 250)",
  grid: "oklch(90% 0.012 240)",
  tick: "oklch(45% 0.02 250)",
  series: "oklch(48% 0.1 180)",
  flagStatistical: "oklch(62% 0.14 55)",
  flagSpectral: "oklch(48% 0.1 180)",
  fontSans: "IBM Plex Sans, system-ui, sans-serif",
  fontMono: "IBM Plex Mono, ui-monospace, monospace",
};

function readVar(name: string, fallback: string): string {
  if (typeof window === "undefined") {
    return fallback;
  }
  const value = getComputedStyle(document.documentElement)
    .getPropertyValue(name)
    .trim();
  return value || fallback;
}

export function getChartTheme(): ChartTheme {
  return {
    ink: readVar("--fft-chart-ink", FALLBACK.ink),
    grid: readVar("--fft-chart-grid", FALLBACK.grid),
    tick: readVar("--fft-chart-tick", FALLBACK.tick),
    series: readVar("--fft-chart-series", FALLBACK.series),
    flagStatistical: readVar(
      "--fft-flag-statistical",
      FALLBACK.flagStatistical,
    ),
    flagSpectral: readVar("--fft-flag-spectral", FALLBACK.flagSpectral),
    fontSans: readVar("--font-sans", FALLBACK.fontSans),
    fontMono: readVar("--font-mono", FALLBACK.fontMono),
  };
}

/** Static RGBA approximations for canvas overlays (CSS oklch not always paintable). */
export const FLAG_OVERLAY_RGBA = {
  statistical: "rgba(180, 110, 20, 0.18)",
  spectral: "rgba(20, 130, 120, 0.18)",
} as const;

/** Theme-aware RGBA for canvas overlays (CSS color strings not always paintable). */
export function getFlagOverlayRgba(): Record<string, string> {
  const theme =
    typeof document !== "undefined"
      ? document.documentElement.getAttribute("data-theme")
      : null;
  if (theme === "solarized-dark") {
    return {
      statistical: "rgba(181, 137, 0, 0.28)",
      spectral: "rgba(42, 161, 152, 0.28)",
    };
  }
  return {
    statistical: FLAG_OVERLAY_RGBA.statistical,
    spectral: FLAG_OVERLAY_RGBA.spectral,
  };
}

export const FLAG_LEGEND_SWATCH = {
  statistical: "bg-[color-mix(in_oklch,var(--fft-flag-statistical)_40%,transparent)]",
  spectral: "bg-[color-mix(in_oklch,var(--fft-flag-spectral)_40%,transparent)]",
} as const;
