"use client";

/**
 * Colourblind / numeric policy (R8): viridis-like blue→teal→yellow sequential
 * palette (not red–green). Always ship a numeric table toggle alongside the
 * canvas heatmap. Missing cells render as gaps, never silent zeros.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { formatMaybeNumber, formatUtc } from "@/lib/format";
import { LinkDocsMore } from "@/components/docs/LinkDocsMore";
import { CHART_CAPTIONS } from "@/lib/detectors";
import { docsChartsHref } from "@/lib/docs-links";
import { formatPeriodHours } from "@/lib/period-hours";
import type { StftMatrixResponse } from "@/lib/types";

type ChartEntityStftHeatmapProps = {
  matrix: StftMatrixResponse;
};

/** Approximate viridis stops (colourblind-safer than red–green). */
const VIRIDIS: [number, number, number][] = [
  [68, 1, 84],
  [59, 82, 139],
  [33, 145, 140],
  [94, 201, 98],
  [253, 231, 37],
];

function lerpChannel(a: number, b: number, t: number): number {
  return Math.round(a + (b - a) * t);
}

function colourFor(t: number): string {
  const x = Math.min(1, Math.max(0, t));
  const scaled = x * (VIRIDIS.length - 1);
  const i = Math.min(VIRIDIS.length - 2, Math.floor(scaled));
  const local = scaled - i;
  const c0 = VIRIDIS[i];
  const c1 = VIRIDIS[i + 1];
  return `rgb(${lerpChannel(c0[0], c1[0], local)}, ${lerpChannel(c0[1], c1[1], local)}, ${lerpChannel(c0[2], c1[2], local)})`;
}

export function ChartEntityStftHeatmap({ matrix }: ChartEntityStftHeatmapProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [showNumeric, setShowNumeric] = useState(false);

  const finitePowers = useMemo(() => {
    const values: number[] = [];
    for (const row of matrix.power) {
      for (const cell of row) {
        if (cell !== null && Number.isFinite(cell)) {
          values.push(cell);
        }
      }
    }
    return values;
  }, [matrix.power]);

  const maxPower = finitePowers.length ? Math.max(...finitePowers) : 0;

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || matrix.n_freq === 0 || matrix.n_time === 0) {
      return;
    }
    const cellW = 4;
    const cellH = 4;
    const width = Math.max(1, matrix.n_time * cellW);
    const height = Math.max(1, matrix.n_freq * cellH);
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext("2d");
    if (!ctx) {
      return;
    }
    ctx.fillStyle = getComputedStyle(document.documentElement)
      .getPropertyValue("--color-base-100")
      .trim() || "#f7f8fa";
    ctx.fillRect(0, 0, width, height);
    for (let fi = 0; fi < matrix.n_freq; fi += 1) {
      const row = matrix.power[fi] ?? [];
      // Low frequency at bottom (spectrogram convention).
      const y = (matrix.n_freq - 1 - fi) * cellH;
      for (let ti = 0; ti < matrix.n_time; ti += 1) {
        const cell = row[ti];
        if (cell === null || !Number.isFinite(cell) || maxPower <= 0) {
          continue;
        }
        ctx.fillStyle = colourFor(cell / maxPower);
        ctx.fillRect(ti * cellW, y, cellW, cellH);
      }
    }
  }, [matrix, maxPower]);

  if (matrix.empty_reason) {
    return (
      <div role="status" className="alert">
        <span>
          STFT matrix unavailable ({matrix.empty_reason}). Need at least{" "}
          <code>{matrix.window_buckets}</code> buckets for the configured
          window.
        </span>
      </div>
    );
  }

  const numericRows = showNumeric
    ? matrix.power.slice(0, Math.min(12, matrix.n_freq))
    : [];
  const numericCols = Math.min(8, matrix.n_time);

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="text-base font-semibold">STFT power heatmap</h3>
        <button
          type="button"
          className="btn btn-ghost btn-xs"
          onClick={() => setShowNumeric((value) => !value)}
        >
          {showNumeric ? "Hide numeric table" : "Show numeric table"}
        </button>
      </div>
      <p className="text-sm opacity-70">
        {CHART_CAPTIONS.stft}{" "}
        <LinkDocsMore href={docsChartsHref("stft")}>Charts in Docs</LinkDocsMore>
      </p>
      <p className="text-sm text-base-content/60">
        Colourblind-safe sequential palette (viridis-like). Axes: time →,
        frequency ↑ (low at bottom). Cells are{" "}
        <code>
          {matrix.n_freq}×{matrix.n_time}
        </code>
        {matrix.capped ? " (capped)" : ""}.
        {matrix.truncated_input
          ? " Input series was truncated before STFT."
          : ""}{" "}
        Missing bins stay blank (not zero).
      </p>
      <div className="fft-paper-panel overflow-x-auto p-2">
        <canvas
          ref={canvasRef}
          className="max-w-full"
          role="img"
          aria-label="STFT power heatmap"
        />
      </div>
      {showNumeric ? (
        <div className="overflow-x-auto">
          <table className="table table-xs">
            <thead>
              <tr>
                <th>period_h \\ time</th>
                {matrix.time_starts.slice(0, numericCols).map((ts, index) => (
                  <th key={`t-${index}`} className="font-mono text-xs">
                    {formatUtc(ts).slice(0, 16)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {numericRows.map((row, fi) => (
                <tr key={`f-${fi}`}>
                  <td className="font-mono text-xs">
                    {formatPeriodHours(matrix.period_hours[fi] ?? null)}
                  </td>
                  {row.slice(0, numericCols).map((cell, ti) => (
                    <td key={`c-${fi}-${ti}`} className="font-mono text-xs">
                      {cell === null ? "—" : formatMaybeNumber(cell, 3)}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
          <p className="mt-1 text-xs text-base-content/60">
            Showing up to 12×8 cells of the capped matrix for readability.
          </p>
        </div>
      ) : null}
    </div>
  );
}
