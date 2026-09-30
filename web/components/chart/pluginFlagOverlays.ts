import { getFlagOverlayRgba } from "@/lib/chart-theme";
import type { ChartType, Plugin } from "chart.js";
import type { FlaggedWindow } from "@/lib/types";

export type FlagOverlayPluginOptions = {
  overlays: FlaggedWindow[];
};

declare module "chart.js" {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  interface PluginOptionsByType<TType extends ChartType> {
    flagOverlays?: FlagOverlayPluginOptions;
  }
}

function parseTime(value: string | null | undefined): number | null {
  if (!value) {
    return null;
  }
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
}

export const flagOverlaysPlugin: Plugin<"line", FlagOverlayPluginOptions> = {
  id: "flagOverlays",
  afterDatasetsDraw(chart, _args, options) {
    const overlays = options?.overlays ?? [];
    const labels = chart.data.labels ?? [];
    if (!overlays.length || !labels.length) {
      return;
    }
    const xScale = chart.scales.x;
    const area = chart.chartArea;
    if (!xScale || !area) {
      return;
    }
    const ctx = chart.ctx;
    overlays.forEach((band) => {
      const start = parseTime(band.window_start);
      const end = parseTime(band.window_end);
      if (start === null || end === null) {
        return;
      }
      let leftIndex = 0;
      let rightIndex = labels.length - 1;
      labels.forEach((label, index) => {
        const ts = parseTime(typeof label === "string" ? label : String(label));
        if (ts === null) {
          return;
        }
        if (ts <= start) {
          leftIndex = index;
        }
        if (ts <= end) {
          rightIndex = index;
        }
      });
      let x1 = xScale.getPixelForValue(leftIndex);
      let x2 = xScale.getPixelForValue(rightIndex);
      if (x2 < x1) {
        const tmp = x1;
        x1 = x2;
        x2 = tmp;
      }
      const width = Math.max(2, x2 - x1);
      ctx.save();
      const overlayColors = getFlagOverlayRgba();
      ctx.fillStyle = overlayColors[band.source] ?? "rgba(26, 26, 26, 0.12)";
      ctx.fillRect(x1, area.top, width, area.bottom - area.top);
      ctx.restore();
    });
  },
};
