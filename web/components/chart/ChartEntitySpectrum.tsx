"use client";

/**
 * Colourblind / numeric policy (R8): this PSD is a near-grayscale line chart,
 * not a spectrogram heatmap. STFT heatmap lives in ChartEntityStftHeatmap
 * (Phase 60) with a viridis-like palette + numeric table toggle.
 */

import { useEffect, useRef, useState } from "react";
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
import { useTheme } from "@/components/theme/ProviderTheme";
import { getChartTheme } from "@/lib/chart-theme";
import { formatPeriodHours, periodHours } from "@/lib/period-hours";
import { LinkDocsMore } from "@/components/docs/LinkDocsMore";
import { CHART_CAPTIONS } from "@/lib/detectors";
import { docsChartsHref } from "@/lib/docs-links";

Chart.register(
  LineController,
  LineElement,
  PointElement,
  LinearScale,
  CategoryScale,
  Filler,
  Tooltip,
  Legend,
);

type ChartEntitySpectrumProps = {
  freqGrid: number[];
  psdNorm: number[];
  downsampled: boolean;
  bucketSeconds: number | null;
};

export function ChartEntitySpectrum({
  freqGrid,
  psdNorm,
  downsampled,
  bucketSeconds,
}: ChartEntitySpectrumProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const chartRef = useRef<Chart<"line"> | null>(null);
  const [showNumeric, setShowNumeric] = useState(false);
  const { theme: themeId } = useTheme();

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || freqGrid.length === 0 || psdNorm.length === 0) {
      return;
    }

    chartRef.current?.destroy();
    const theme = getChartTheme();
    const periodLabels = freqGrid.map((freq) =>
      formatPeriodHours(periodHours(freq, bucketSeconds)),
    );

    chartRef.current = new Chart(canvas, {
      type: "line",
      data: {
        labels: periodLabels,
        datasets: [
          {
            label: "psd_norm",
            data: psdNorm,
            borderColor: theme.series,
            backgroundColor: "rgba(20, 130, 120, 0.08)",
            borderWidth: 1.25,
            pointRadius: 0,
            tension: 0,
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
            callbacks: {
              title(items) {
                const index = items[0]?.dataIndex ?? 0;
                const freq = freqGrid[index];
                const hours = periodHours(freq ?? 0, bucketSeconds);
                if (hours === null) {
                  return "DC (f = 0)";
                }
                return `period ${formatPeriodHours(hours)} h`;
              },
              afterBody(items) {
                const index = items[0]?.dataIndex ?? 0;
                const freq = freqGrid[index];
                if (freq == null) {
                  return [];
                }
                return [`freq ${freq.toFixed(6)} cycles/bucket`];
              },
            },
          },
        },
        scales: {
          x: {
            title: {
              display: true,
              text: "period (hours)",
              color: theme.tick,
              font: { family: theme.fontSans, size: 11 },
            },
            ticks: {
              color: theme.tick,
              maxRotation: 0,
              autoSkip: true,
              maxTicksLimit: 8,
              font: { family: theme.fontMono, size: 10 },
            },
            grid: { color: theme.grid },
          },
          y: {
            beginAtZero: true,
            title: {
              display: true,
              text: "normalized PSD",
              color: theme.tick,
              font: { family: theme.fontSans, size: 11 },
            },
            ticks: {
              color: theme.tick,
              font: { family: theme.fontMono, size: 10 },
            },
            grid: { color: theme.grid },
          },
        },
      },
    });

    return () => {
      chartRef.current?.destroy();
      chartRef.current = null;
    };
  }, [freqGrid, psdNorm, bucketSeconds, themeId]);

  if (freqGrid.length === 0 || psdNorm.length === 0) {
    return (
      <div className="alert">
        <span>Spectral features present, but no baseline PSD arrays.</span>
      </div>
    );
  }

  return (
    <div className="fft-paper-panel p-4">
      <h3 className="mb-1 text-sm font-medium opacity-80">
        Normalized PSD
        {downsampled ? (
          <span className="ml-2 font-normal text-base-content/60">(downsampled)</span>
        ) : null}
      </h3>
      <p className="mb-2 text-sm opacity-70">
        {CHART_CAPTIONS.psd}{" "}
        <LinkDocsMore href={docsChartsHref("psd")}>Charts in Docs</LinkDocsMore>
      </p>
      <p className="mb-3 text-sm text-base-content/60">
        Primary axis: period hours = (1/f) ×{" "}
        {bucketSeconds ?? "bucket_seconds"} / 3600. Frequency stays in the
        tooltip.
      </p>
      <div className="h-64">
        <canvas ref={canvasRef} aria-label="PSD chart" role="img" />
      </div>
      <p className="mt-3">
        <button
          type="button"
          className="btn btn-sm btn-ghost"
          onClick={() => setShowNumeric((current) => !current)}
        >
          {showNumeric ? "Hide numeric PSD table" : "Show numeric PSD table"}
        </button>
      </p>
      {showNumeric ? (
        <div className="mt-3 max-h-64 overflow-auto">
          <table className="table table-xs">
            <caption className="text-left text-sm opacity-70">
              period_hours, freq_grid (cycles / bucket), and psd_norm
            </caption>
            <thead>
              <tr>
                <th>period_hours</th>
                <th>freq_grid</th>
                <th>psd_norm</th>
              </tr>
            </thead>
            <tbody>
              {freqGrid.map((freq, index) => (
                <tr key={`${freq}-${index}`}>
                  <td className="font-mono">
                    {formatPeriodHours(periodHours(freq, bucketSeconds))}
                  </td>
                  <td className="font-mono">{freq.toFixed(6)}</td>
                  <td className="font-mono">
                    {psdNorm[index] != null ? psdNorm[index].toFixed(4) : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
}
