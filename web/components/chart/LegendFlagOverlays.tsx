"use client";

const SOURCE_META: Record<string, { label: string; swatch: string }> = {
  statistical: {
    label: "statistical (rate)",
    swatch:
      "bg-[color-mix(in_oklch,var(--fft-flag-statistical)_40%,transparent)]",
  },
  spectral: {
    label: "spectral (rhythm)",
    swatch:
      "bg-[color-mix(in_oklch,var(--fft-flag-spectral)_40%,transparent)]",
  },
};

const DEFAULT_SOURCES = ["statistical", "spectral"] as const;

type LegendFlagOverlaysProps = {
  enabledSources: ReadonlySet<string>;
  onToggle: (source: string) => void;
  availableSources?: readonly string[];
};

export function LegendFlagOverlays({
  enabledSources,
  onToggle,
  availableSources = DEFAULT_SOURCES,
}: LegendFlagOverlaysProps) {
  const sources =
    availableSources.length > 0 ? availableSources : [...DEFAULT_SOURCES];

  return (
    <div
      className="flex flex-wrap gap-4 text-sm text-base-content/70"
      aria-label="Chart overlay toggles"
    >
      {sources.map((source) => {
        const meta = SOURCE_META[source] ?? {
          label: source,
          swatch: "bg-base-content/20",
        };
        const checked = enabledSources.has(source);
        const id = `overlay-${source}`;
        return (
          <label
            key={source}
            htmlFor={id}
            className="inline-flex cursor-pointer items-center gap-2"
          >
            <input
              id={id}
              type="checkbox"
              className="checkbox checkbox-xs"
              checked={checked}
              onChange={() => onToggle(source)}
            />
            <span className={`inline-block h-3 w-4 rounded-sm ${meta.swatch}`} />
            {meta.label}
          </label>
        );
      })}
    </div>
  );
}

export { DEFAULT_SOURCES as OVERLAY_SOURCE_DEFAULTS };
