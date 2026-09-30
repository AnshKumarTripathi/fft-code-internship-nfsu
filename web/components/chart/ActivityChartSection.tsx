"use client";

import { useMemo, useState } from "react";
import { ChartEntityActivity } from "@/components/chart/ChartEntityActivity";
import { LegendFlagOverlays, OVERLAY_SOURCE_DEFAULTS } from "@/components/chart/LegendFlagOverlays";
import { LinkDocsMore } from "@/components/docs/LinkDocsMore";
import { CHART_CAPTIONS } from "@/lib/detectors";
import { docsChartsHref } from "@/lib/docs-links";
import type { BucketPoint, FlaggedWindow } from "@/lib/types";

type ActivityChartSectionProps = {
  items: BucketPoint[];
  overlays: FlaggedWindow[];
  emptyMessage?: string;
  ariaLabel?: string;
};

function collectSources(overlays: FlaggedWindow[]): string[] {
  const found = new Set<string>(OVERLAY_SOURCE_DEFAULTS);
  for (const band of overlays) {
    if (band.source) {
      found.add(band.source);
    }
  }
  return [...found];
}

export function ActivityChartSection({
  items,
  overlays,
  emptyMessage,
  ariaLabel,
}: ActivityChartSectionProps) {
  const availableSources = useMemo(
    () => collectSources(overlays),
    [overlays],
  );
  const [enabledSources, setEnabledSources] = useState(
    () => new Set<string>(OVERLAY_SOURCE_DEFAULTS),
  );

  function handleToggle(source: string) {
    setEnabledSources((current) => {
      const next = new Set(current);
      if (next.has(source)) {
        next.delete(source);
      } else {
        next.add(source);
      }
      return next;
    });
  }

  const filteredOverlays = overlays.filter((band) =>
    enabledSources.has(band.source),
  );

  return (
    <>
      <p className="text-sm opacity-70">
        {CHART_CAPTIONS.activity}{" "}
        <LinkDocsMore href={docsChartsHref("activity")}>
          Charts in Docs
        </LinkDocsMore>
      </p>
      <LegendFlagOverlays
        enabledSources={enabledSources}
        onToggle={handleToggle}
        availableSources={availableSources}
      />
      <ChartEntityActivity
        items={items}
        overlays={filteredOverlays}
        emptyMessage={emptyMessage}
        ariaLabel={ariaLabel}
      />
    </>
  );
}
