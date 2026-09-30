import { ActivityChartSection } from "@/components/chart/ActivityChartSection";
import { ChartEntitySpectrum } from "@/components/chart/ChartEntitySpectrum";
import { DetailsStftHeatmap } from "@/components/chart/DetailsStftHeatmap";
import { CardSpectralFeatures } from "@/components/entity/CardSpectralFeatures";
import { AlertApiDown } from "@/components/feedback/AlertApiDown";
import { AlertAnalysisWindow } from "@/components/feedback/AlertAnalysisWindow";
import { AlertChartPartial } from "@/components/feedback/AlertChartPartial";
import { AlertWarehouseBusy } from "@/components/feedback/AlertWarehouseBusy";
import { DetailsSpectral } from "@/components/layout/DetailsSpectral";
import { fetchEntityBuckets, fetchEntitySpectrum } from "@/lib/api";
import { entityAnalysisHref } from "@/lib/hrefs";
import type { BucketPoint, FlaggedWindow, SpectrumResponse } from "@/lib/types";
import { resolveEntityWindow, type EntityWindowQuery } from "@/lib/window";

type EntityAnalysisPanelProps = {
  entityId: string;
  query: EntityWindowQuery;
};

export async function EntityAnalysisPanel({
  entityId,
  query,
}: EntityAnalysisPanelProps) {
  const window = resolveEntityWindow(query);
  const retryHref = entityAnalysisHref(
    entityId,
    window.startParam,
    window.endParam,
    window.hasWindow ? window.padHours : undefined,
  );

  const [bucketsResult, spectrumResult] = await Promise.all([
    fetchEntityBuckets(entityId, {
      start: window.windowStart,
      end: window.windowEnd,
      order: window.order,
    }),
    fetchEntitySpectrum(entityId, true),
  ]);

  if (!bucketsResult.ok && (bucketsResult.reason === "warehouse_busy" || bucketsResult.reason === "warehouse_missing")) {
    return <AlertWarehouseBusy retryHref={retryHref} />;
  }
  if (!spectrumResult.ok && (spectrumResult.reason === "warehouse_busy" || spectrumResult.reason === "warehouse_missing")) {
    return <AlertWarehouseBusy retryHref={retryHref} />;
  }
  if (
    !bucketsResult.ok &&
    !spectrumResult.ok &&
    bucketsResult.reason === "api_down" &&
    spectrumResult.reason === "api_down"
  ) {
    return <AlertApiDown />;
  }

  let bucketItems: BucketPoint[] = [];
  let overlays: FlaggedWindow[] = [];
  if (bucketsResult.ok) {
    bucketItems = bucketsResult.data.items;
    overlays = bucketsResult.data.overlays;
  }

  const spectrumFailed =
    !spectrumResult.ok && spectrumResult.status !== 404;
  const spectrum: SpectrumResponse | null = spectrumResult.ok
    ? spectrumResult.data
    : null;
  const hasPsd =
    spectrum !== null &&
    spectrum.freq_grid.length > 0 &&
    spectrum.psd_norm.length > 0;

  return (
    <div className="flex flex-col gap-8">
      <AlertAnalysisWindow />
      <section className="flex flex-col gap-3">
        <h2 className="text-lg font-semibold">Activity (entity_bucket_counts, UTC)</h2>
        {bucketsResult.ok ? (
          <ActivityChartSection items={bucketItems} overlays={overlays} />
        ) : (
          <AlertChartPartial source="activity buckets" />
        )}
      </section>
      <section className="flex flex-col gap-4">
        <h2 className="text-lg font-semibold">Spectral fingerprint</h2>
        {spectrumFailed ? (
          <AlertChartPartial source="baseline PSD" />
        ) : spectrum ? (
          <DetailsSpectral>
            <CardSpectralFeatures spectrum={spectrum} />
            {hasPsd ? (
              <ChartEntitySpectrum
                freqGrid={spectrum.freq_grid}
                psdNorm={spectrum.psd_norm}
                downsampled={spectrum.downsampled}
                bucketSeconds={spectrum.bucket_seconds}
              />
            ) : (
              <div className="alert">
                <span>
                  Spectral features present, but no baseline PSD arrays.
                </span>
              </div>
            )}
          </DetailsSpectral>
        ) : (
          <div className="alert">
            <span>
              No spectral_baselines or entity_spectral_features for this
              entity.
            </span>
          </div>
        )}
        <DetailsStftHeatmap
          entityId={entityId}
          start={window.windowStart}
          end={window.windowEnd}
        />
      </section>
    </div>
  );
}
