"use client";

import { useEffect, useRef } from "react";
import {
  CategoryScale,
  Chart,
  Filler,
  Legend,
  LineController,
  LineElement,
  LinearScale,
  PointElement,
  Tooltip,
} from "chart.js";
import type {} from "chartjs-plugin-zoom";
import { flagOverlaysPlugin } from "@/components/chart/pluginFlagOverlays";
import { useTheme } from "@/components/theme/ProviderTheme";
import { getChartTheme } from "@/lib/chart-theme";
import type { BucketPoint, FlaggedWindow } from "@/lib/types";

Chart.register(
  LineController,
  LineElement,
  PointElement,
  LinearScale,
  CategoryScale,
  Filler,
  Tooltip,
  Legend,
  flagOverlaysPlugin,
);

type ChartEntityActivityProps = {
  items: BucketPoint[];
  overlays: FlaggedWindow[];
  emptyMessage?: string;
  ariaLabel?: string;
};

function pad2(value: number): string {
  return value < 10 ? `0${value}` : String(value);
}

function formatUtcTick(value: string): string {
  if (!value) {
    return "";
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value.slice(5, 16);
  }
  return `${pad2(parsed.getUTCMonth() + 1)}-${pad2(parsed.getUTCDate())} ${pad2(parsed.getUTCHours())}:${pad2(parsed.getUTCMinutes())}`;
}

export function ChartEntityActivity({
  items,
  overlays,
  emptyMessage = "No entity_bucket_counts rows for this entity.",
  ariaLabel = "Entity activity chart",
}: ChartEntityActivityProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const chartRef = useRef<Chart<"line"> | null>(null);
  const { theme: themeId } = useTheme();

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || items.length === 0) {
      return;
    }

    let cancelled = false;

    void (async () => {
      // hammerjs touches `window` at import time — load zoom plugin only in the browser.
      const { default: zoomPlugin } = await import("chartjs-plugin-zoom");
      if (cancelled || !canvasRef.current) {
        return;
      }

      Chart.register(zoomPlugin);
      chartRef.current?.destroy();
      const labels = items.map((point) => point.bucket_start ?? "");
      const values = items.map((point) => point.event_count);
      const theme = getChartTheme();

      chartRef.current = new Chart(canvasRef.current, {
        type: "line",
        data: {
          labels,
          datasets: [
            {
              label: "event_count",
              data: values,
              borderColor: theme.series,
              backgroundColor: "rgba(20, 130, 120, 0.12)",
              borderWidth: 1.5,
              pointRadius: 0,
              tension: 0.15,
              fill: true,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: false,
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: theme.ink,
              titleFont: { family: theme.fontMono, size: 11 },
              bodyFont: { family: theme.fontMono, size: 11 },
            },
            flagOverlays: { overlays },
            zoom: {
              limits: {
                x: { min: "original", max: "original", minRange: 2 },
              },
              pan: {
                enabled: true,
                mode: "x",
              },
              zoom: {
                wheel: { enabled: true },
                pinch: { enabled: true },
                mode: "x",
              },
            },
          },
          scales: {
            x: {
              ticks: {
                color: theme.tick,
                maxRotation: 0,
                autoSkip: true,
                maxTicksLimit: 8,
                font: { family: theme.fontMono, size: 10 },
                callback(_tickValue, index) {
                  const label = labels[index] ?? "";
                  return formatUtcTick(label);
                },
              },
              grid: { color: theme.grid },
            },
            y: {
              beginAtZero: true,
              ticks: {
                color: theme.tick,
                font: { family: theme.fontMono, size: 10 },
              },
              grid: { color: theme.grid },
            },
          },
        },
      });
    })();

    return () => {
      cancelled = true;
      chartRef.current?.destroy();
      chartRef.current = null;
    };
  }, [items, overlays, themeId]);

  function handleResetZoom() {
    chartRef.current?.resetZoom();
  }

  if (items.length === 0) {
    return (
      <div className="alert">
        <span>{emptyMessage}</span>
      </div>
    );
  }

  return (
    <div className="fft-paper-panel p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-sm font-medium opacity-80">
          event_count per bucket with flagged overlays (UTC)
        </h3>
        <button
          type="button"
          className="btn btn-ghost btn-xs"
          onClick={handleResetZoom}
        >
          Reset zoom
        </button>
      </div>
      <p className="mb-2 text-xs text-base-content/60">
        Scroll to zoom · drag to pan
      </p>
      <div className="h-64">
        <canvas ref={canvasRef} aria-label={ariaLabel} role="img" />
      </div>
    </div>
  );
}
