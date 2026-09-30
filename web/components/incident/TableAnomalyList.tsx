import { DETECTOR_ORDER, detectorRole } from "@/lib/detectors";
import { anomalyDisposition } from "@/lib/actions";
import { formatUtc } from "@/lib/format";
import { entityEventsHref } from "@/lib/hrefs";
import type { AnalystActionItem, AnomalyItem } from "@/lib/types";
import Link from "next/link";
import { BadgeFlagBand } from "@/components/incident/BadgeFlagBand";

type TableAnomalyListProps = {
  anomalies: AnomalyItem[];
  total?: number;
  actions?: AnalystActionItem[];
};

export function TableAnomalyList({
  anomalies,
  total,
  actions = [],
}: TableAnomalyListProps) {
  const grouped = new Map<string, AnomalyItem[]>();
  for (const detector of DETECTOR_ORDER) {
    grouped.set(detector, []);
  }
  for (const anomaly of anomalies) {
    const bucket = grouped.get(anomaly.source_detector) ?? [];
    bucket.push(anomaly);
    grouped.set(anomaly.source_detector, bucket);
  }
  const shown = anomalies.length;
  const all = total ?? shown;

  return (
    <section className="flex flex-col gap-3">
      <h2 className="text-lg font-semibold">Contributing anomalies</h2>
      {anomalies.length === 0 ? (
        <div className="alert">
          <span>No anomaly_events rows for contributing_anomaly_ids.</span>
        </div>
      ) : (
        <>
          <p className="text-sm opacity-70">
            showing {shown} of {all} (highest |score|) · z vs cutoff, not
            four-decimal precision
          </p>
          {Array.from(grouped.entries())
            .filter(([, rows]) => rows.length > 0)
            .map(([detector, rows]) => (
              <div key={detector} className="flex flex-col gap-2">
                <h3 className="text-sm font-medium">
                  {detector}{" "}
                  <span className="opacity-70">({detectorRole(detector)})</span>
                </h3>
                <div className="fft-paper-panel overflow-x-auto">
                  <table className="table table-sm">
                    <thead>
                      <tr>
                        <th>Flag</th>
                        <th>Status</th>
                        <th>z vs threshold</th>
                        <th>Window start (UTC)</th>
                        <th>Window end (UTC)</th>
                        <th>Events</th>
                      </tr>
                    </thead>
                    <tbody>
                      {rows.map((anomaly) => {
                        const expl = anomaly.explanation;
                        const disposition = anomalyDisposition(
                          actions,
                          anomaly.anomaly_id,
                        );
                        return (
                          <tr key={anomaly.anomaly_id}>
                            <td>
                              <BadgeFlagBand
                                band={expl.uncertainty?.band}
                                flagged
                              />
                            </td>
                            <td>
                              {disposition === "dismissed" ? (
                                <span className="badge">dismissed</span>
                              ) : (
                                <span className="badge badge-outline">open</span>
                              )}
                            </td>
                            <td className="font-mono text-sm">
                              {expl.uncertainty?.display ?? "—"}
                            </td>
                            <td className="font-mono text-sm">
                              {formatUtc(anomaly.window_start)}
                            </td>
                            <td className="font-mono text-sm">
                              {formatUtc(anomaly.window_end)}
                            </td>
                            <td>
                              <Link
                                className="link text-sm"
                                href={entityEventsHref(
                                  anomaly.entity_id,
                                  anomaly.window_start,
                                  anomaly.window_end,
                                )}
                              >
                                View window
                              </Link>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            ))}
        </>
      )}
    </section>
  );
}
