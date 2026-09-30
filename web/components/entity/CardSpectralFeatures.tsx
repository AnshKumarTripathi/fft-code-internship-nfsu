import { formatMaybeNumber, formatUtc } from "@/lib/format";
import type { SpectralWindowScore, SpectrumResponse } from "@/lib/types";
import { BadgeFlagBand } from "@/components/incident/BadgeFlagBand";

type CardSpectralFeaturesProps = {
  spectrum: SpectrumResponse | null;
};

function ScoreRow({ score }: { score: SpectralWindowScore }) {
  return (
    <tr>
      <td className="font-mono text-sm">{formatUtc(score.window_start)}</td>
      <td className="font-mono text-sm">{formatUtc(score.window_end)}</td>
      <td className="font-mono text-sm">
        {formatMaybeNumber(score.energy_z, 1)}
      </td>
      <td className="font-mono text-sm">
        {formatMaybeNumber(score.shape_js_z, 1)}
      </td>
      <td>
        <BadgeFlagBand band={score.band} flagged={score.flagged} />
      </td>
      <td className="font-mono text-sm">{score.display ?? "—"}</td>
    </tr>
  );
}

export function CardSpectralFeatures({ spectrum }: CardSpectralFeaturesProps) {
  if (!spectrum) {
    return null;
  }
  const features = spectrum.features;
  if (!features) {
    return null;
  }

  return (
    <>
      <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <div>
          <dt className="text-xs uppercase opacity-60">Dominant period (h)</dt>
          <dd className="font-mono">
            {formatMaybeNumber(features.dominant_period_hours, 1)}
          </dd>
        </div>
        <div>
          <dt className="text-xs uppercase opacity-60">Dominant power frac</dt>
          <dd className="font-mono">
            {formatMaybeNumber(features.dominant_power_frac, 2)}
          </dd>
        </div>
        <div>
          <dt className="text-xs uppercase opacity-60">Spectral entropy</dt>
          <dd className="font-mono">
            {formatMaybeNumber(features.spectral_entropy, 2)}
          </dd>
        </div>
        <div>
          <dt className="text-xs uppercase opacity-60">Total power</dt>
          <dd className="font-mono">
            {formatMaybeNumber(features.total_power, 2)}
          </dd>
        </div>
        <div>
          <dt className="text-xs uppercase opacity-60">Computed at (UTC)</dt>
          <dd className="font-mono text-sm">
            {formatUtc(features.computed_at)}
          </dd>
        </div>
      </dl>
      {spectrum.recent_scores.length ? (
        <>
          <h3 className="text-sm font-medium opacity-80">
            Recent spectral_window_scores
            {spectrum.z_threshold != null
              ? ` · cutoff ${spectrum.z_threshold}`
              : null}
            {spectrum.warn_band != null
              ? ` · warn_band ${spectrum.warn_band}`
              : null}
          </h3>
          <div className="overflow-x-auto">
            <table className="table table-sm">
              <thead>
                <tr>
                  <th>Window start (UTC)</th>
                  <th>Window end (UTC)</th>
                  <th>energy_z</th>
                  <th>shape_js_z</th>
                  <th>Flag</th>
                  <th>z vs threshold</th>
                </tr>
              </thead>
              <tbody>
                {spectrum.recent_scores.map((score, index) => (
                  <ScoreRow
                    key={`${score.window_start ?? "score"}-${index}`}
                    score={score}
                  />
                ))}
              </tbody>
            </table>
          </div>
        </>
      ) : null}
    </>
  );
}
