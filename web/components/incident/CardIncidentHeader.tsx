import Link from "next/link";
import { DETECTOR_ORDER, detectorLabel } from "@/lib/detectors";
import {
  displayValue,
  formatMaybeNumber,
  formatUtc,
  severityBadgeClass,
  shortId,
} from "@/lib/format";
import { entityHref } from "@/lib/hrefs";
import type { EntityMeta, IncidentDetail } from "@/lib/types";

type CardIncidentHeaderProps = {
  incident: IncidentDetail;
  entity: EntityMeta | null;
};

const EDGE_ORDER = ["precedes", "same_session", "same_ip", "same_host"];

export function CardIncidentHeader({
  incident,
  entity,
}: CardIncidentHeaderProps) {
  const detectorSet = incident.detector_set ?? [];
  const presentDetectors = new Set(
    detectorSet.length
      ? detectorSet
      : incident.anomalies.map((anomaly) => anomaly.source_detector),
  );
  const windowHref = entityHref(
    incident.entity_id,
    incident.start_time,
    incident.end_time,
  );
  const anomalyCount =
    incident.anomalies_total ||
    incident.anomaly_count ||
    incident.contributing_anomaly_ids.length ||
    incident.anomalies.length;
  const edgeCounts = incident.edge_counts ?? {};
  const title =
    incident.summary_text?.trim() ||
    `Incident on ${incident.entity_id}`;

  return (
    <header className="flex flex-col gap-4">
      <p className="text-xs uppercase tracking-wide text-base-content/60">
        <Link href="/incidents" className="link normal-case tracking-normal">
          Triage
        </Link>
        {" / "}
        <span className="fft-mono-meta normal-case" title={incident.incident_id}>
          {shortId(incident.incident_id)}
        </span>
      </p>
      <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
      <p className="text-sm">
        Severity{" "}
        <span className={severityBadgeClass(incident.severity)}>
          {incident.severity}
        </span>{" "}
        for entity{" "}
        <Link className="link" href={windowHref}>
          {incident.entity_id}
        </Link>
        .
      </p>
      <p className="flex flex-wrap gap-2" aria-label="Detectors">
        {DETECTOR_ORDER.map((detector) => {
          const isOn = presentDetectors.has(detector);
          return (
            <span
              key={detector}
              className={
                isOn
                  ? "badge badge-info"
                  : "badge badge-ghost opacity-50"
              }
            >
              {detectorLabel(detector)}
            </span>
          );
        })}
      </p>
      <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <div>
          <dt className="text-xs uppercase tracking-wide text-base-content/60">
            Entity
          </dt>
          <dd>
            <Link className="link text-sm" href={windowHref}>
              {incident.entity_id}
            </Link>
          </dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wide text-base-content/60">
            Type
          </dt>
          <dd>{displayValue(entity?.entity_type)}</dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wide text-base-content/60">
            Label
          </dt>
          <dd>{displayValue(entity?.label)}</dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wide text-base-content/60">
            Incident id
          </dt>
          <dd className="fft-mono-meta" title={incident.incident_id}>
            {shortId(incident.incident_id, 12)}
          </dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wide text-base-content/60">
            Start (UTC)
          </dt>
          <dd className="fft-mono-meta">{formatUtc(incident.start_time)}</dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wide text-base-content/60">
            End (UTC)
          </dt>
          <dd className="fft-mono-meta">{formatUtc(incident.end_time)}</dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wide text-base-content/60">
            Contributing anomalies
          </dt>
          <dd>{anomalyCount}</dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wide text-base-content/60">
            Top score (1 decimal)
          </dt>
          <dd className="fft-mono-meta">
            {formatMaybeNumber(incident.top_score, 1)}
          </dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wide text-base-content/60">
            IP linkage
          </dt>
          <dd>{incident.has_ip_link ? "yes" : "no"}</dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wide text-base-content/60">
            Host linkage
          </dt>
          <dd>{incident.has_host_link ? "yes" : "no"}</dd>
        </div>
      </dl>
      <p className="flex flex-wrap gap-2 text-sm" aria-label="Edge counts">
        {EDGE_ORDER.map((relation) => (
          <span key={relation} className="badge badge-outline">
            {relation} {edgeCounts[relation] ?? 0}
          </span>
        ))}
      </p>
      <section className="fft-section">
        <h2 className="text-base font-semibold">Verdict</h2>
        <div className="fft-paper-panel p-4 text-sm">
          {incident.summary_text || "(no summary_text in warehouse)"}
        </div>
        <p className="text-sm text-base-content/70">
          Statistical flags high rate only; rhythm/sequence use spectral and ML.
          Open Overview for why-flagged and the playbook; Analysis charts are
          behind spectral details.
        </p>
      </section>
    </header>
  );
}
