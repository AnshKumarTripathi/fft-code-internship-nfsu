import Link from "next/link";
import { ActivityChartSection } from "@/components/chart/ActivityChartSection";
import { ChartEntitySpectrum } from "@/components/chart/ChartEntitySpectrum";
import { DetailsStftHeatmap } from "@/components/chart/DetailsStftHeatmap";
import { AlertApiDown } from "@/components/feedback/AlertApiDown";
import { AlertAnalysisWindow } from "@/components/feedback/AlertAnalysisWindow";
import { AlertChartPartial } from "@/components/feedback/AlertChartPartial";
import { AlertWarehouseBusy } from "@/components/feedback/AlertWarehouseBusy";
import { DetailsSpectral } from "@/components/layout/DetailsSpectral";
import {
  fetchEntityBuckets,
  fetchEntitySpectrum,
  fetchIncident,
} from "@/lib/api";
import { entityAnalysisHref, incidentAnalysisHref } from "@/lib/hrefs";
import type { BucketPoint, FlaggedWindow } from "@/lib/types";
import { padIncidentWindow } from "@/lib/window";

type IncidentAnalysisPanelProps = {
  incidentId: string;
};

export async function IncidentAnalysisPanel({
  incidentId,
}: IncidentAnalysisPanelProps) {
  const retryHref = incidentAnalysisHref(incidentId);

  const incidentResult = await fetchIncident(incidentId);
  if (!incidentResult.ok) {
    if (incidentResult.reason === "warehouse_busy" || incidentResult.reason === "warehouse_missing") {
      return <AlertWarehouseBusy retryHref={retryHref} />;
    }
    return <AlertApiDown />;
  }

  const incident = incidentResult.data;
  const padded = padIncidentWindow(incident.start_time, incident.end_time);

  const [bucketsResult, spectrumResult] = await Promise.all([
    fetchEntityBuckets(incident.entity_id, {
      start: padded.start,
      end: padded.end,
      order: "oldest",
    }),
    fetchEntitySpectrum(incident.entity_id, true),
  ]);

  if (!bucketsResult.ok && (bucketsResult.reason === "warehouse_busy" || bucketsResult.reason === "warehouse_missing")) {
    return <AlertWarehouseBusy retryHref={retryHref} />;
  }
  if (!spectrumResult.ok && (spectrumResult.reason === "warehouse_busy" || spectrumResult.reason === "warehouse_missing")) {
    return <AlertWarehouseBusy retryHref={retryHref} />;
  }

  let bucketItems: BucketPoint[] = [];
  let overlays: FlaggedWindow[] = [];
  if (bucketsResult.ok) {
    bucketItems = bucketsResult.data.items;
    overlays = bucketsResult.data.overlays;
  }

  const spectrumFailed =
    !spectrumResult.ok && spectrumResult.status !== 404;
  const spectrum = spectrumResult.ok ? spectrumResult.data : null;
  const hasPsd =
    spectrum !== null &&
    spectrum.freq_grid.length > 0 &&
    spectrum.psd_norm.length > 0;

  return (
    <div className="flex flex-col gap-8">
      <AlertAnalysisWindow />
      <p className="text-sm opacity-70">
        Activity for this incident window. Spectral charts are behind the
        disclosure below. Open{" "}
        <Link
          className="link"
          href={entityAnalysisHref(
            incident.entity_id,
            incident.start_time,
            incident.end_time,
          )}
        >
          entity analysis
        </Link>{" "}
        for the same window.
      </p>
      <section className="flex flex-col gap-3">
        <h2 className="text-lg font-semibold">Activity (incident window, UTC)</h2>
        {bucketsResult.ok ? (
          <ActivityChartSection
            items={bucketItems}
            overlays={overlays}
            emptyMessage="No entity_bucket_counts in the incident window."
            ariaLabel="Incident activity chart"
          />
        ) : (
          <AlertChartPartial source="activity buckets" />
        )}
      </section>
      <section className="flex flex-col gap-3">
        <h2 className="text-lg font-semibold">Spectral fingerprint</h2>
        {spectrumFailed ? (
          <AlertChartPartial source="baseline PSD" />
        ) : (
          <DetailsSpectral>
            {hasPsd && spectrum ? (
              <ChartEntitySpectrum
                freqGrid={spectrum.freq_grid}
                psdNorm={spectrum.psd_norm}
                downsampled={spectrum.downsampled}
                bucketSeconds={spectrum.bucket_seconds}
              />
            ) : (
              <div className="alert">
                <span>No baseline PSD arrays for this entity.</span>
              </div>
            )}
          </DetailsSpectral>
        )}
        <DetailsStftHeatmap
          entityId={incident.entity_id}
          start={padded.start}
          end={padded.end}
        />
      </section>
    </div>
  );
}
