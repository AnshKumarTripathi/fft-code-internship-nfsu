import Link from "next/link";
import { BadgeFlagBand } from "@/components/incident/BadgeFlagBand";
import { FormAnalystAction } from "@/components/incident/FormAnalystAction";
import { ButtonAddToChat } from "@/components/copilot/ButtonAddToChat";
import { LinkDocsMore } from "@/components/docs/LinkDocsMore";
import { anomalyDisposition } from "@/lib/actions";
import { detectorMeaning, detectorRole } from "@/lib/detectors";
import {
  docsDetectorHref,
  docsPlaybooksHref,
  docsThresholdsHref,
  docsWhyFlaggedHref,
} from "@/lib/docs-links";
import { formatMaybeNumber, formatUtc } from "@/lib/format";
import { entityEventsHref } from "@/lib/hrefs";
import type { AnomalyItem, IncidentDetail } from "@/lib/types";

type CardIncidentWhyProps = {
  incident: IncidentDetail;
  defaultOperatorLabel: string;
};

function sourcesLine(anomaly: AnomalyItem): string {
  const sources = anomaly.explanation.log_sources ?? [];
  if (!sources.length) {
    return "Log sources in this window were not recorded.";
  }
  return sources
    .map((row) => `${row.log_source} (${row.event_count})`)
    .join(", ");
}

function whyExcerpt(incident: IncidentDetail): string {
  const lines = [
    `Incident ${incident.incident_id} · severity ${incident.severity}`,
    incident.summary_text ? `Summary: ${incident.summary_text}` : null,
    ...incident.anomalies.slice(0, 5).map((anomaly) => {
      const expl = anomaly.explanation;
      const playbook = expl.playbook?.title
        ? ` Playbook: ${expl.playbook.title}.`
        : "";
      return `- ${expl.detector}: ${expl.headline} (score ${formatMaybeNumber(anomaly.score, 1)}).${playbook}`;
    }),
  ].filter(Boolean);
  return lines.join("\n");
}

export function CardIncidentWhy({
  incident,
  defaultOperatorLabel,
}: CardIncidentWhyProps) {
  const anomalies = incident.anomalies;
  const actions = incident.actions ?? [];

  return (
    <section className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-lg font-semibold">Why flagged</h2>
        <ButtonAddToChat
          label="Why flagged"
          text={whyExcerpt(incident)}
          incidentId={incident.incident_id}
          entityId={incident.entity_id}
          route={`/incidents/${incident.incident_id}/overview`}
        />
      </div>
      <p className="text-sm opacity-70">
        Plain-language lead first; scores and playbooks follow. Cutoff 4.0 is a
        lab heuristic (MAD robust z), not a p-value.{" "}
        <LinkDocsMore href={docsWhyFlaggedHref()}>
          How to read Why flagged
        </LinkDocsMore>
        {" · "}
        <LinkDocsMore href={docsThresholdsHref()}>Thresholds</LinkDocsMore>
      </p>
      {anomalies.length === 0 ? (
        <div role="alert" className="alert">
          <span>No anomaly_events rows for contributing_anomaly_ids.</span>
        </div>
      ) : (
        anomalies.map((anomaly) => {
          const expl = anomaly.explanation;
          const playbook = expl.playbook;
          const disposition = anomalyDisposition(actions, anomaly.anomaly_id);
          const eventsHref = entityEventsHref(
            anomaly.entity_id,
            anomaly.window_start,
            anomaly.window_end,
          );
          const role = detectorRole(expl.detector);
          const meaning = detectorMeaning(expl.detector);
          return (
            <article
              key={anomaly.anomaly_id}
              className="fft-paper-panel bg-base-200 p-4"
            >
              <div className="flex flex-wrap items-center gap-2">
                <BadgeFlagBand band={expl.uncertainty?.band} flagged />
                {disposition === "dismissed" ? (
                  <span className="badge">dismissed</span>
                ) : null}
                <span
                  className="badge badge-outline"
                  title={meaning || undefined}
                >
                  {role}
                </span>
                <span className="font-mono text-sm opacity-70">
                  {expl.detector}
                  {expl.ml?.model_type ? ` · ${expl.ml.model_type}` : null}
                </span>
                <span className="font-mono text-sm">
                  {expl.uncertainty?.display ??
                    formatMaybeNumber(anomaly.score, 1)}
                </span>
              </div>
              <h3 className="mt-3 text-base font-semibold capitalize">{role}</h3>
              {meaning ? (
                <p className="mt-1 text-sm">
                  {meaning}{" "}
                  <LinkDocsMore href={docsDetectorHref(expl.detector)}>
                    Detector maths
                  </LinkDocsMore>
                </p>
              ) : (
                <p className="mt-1 text-sm">
                  <LinkDocsMore href={docsDetectorHref(expl.detector)}>
                    Detector maths
                  </LinkDocsMore>
                </p>
              )}
              {playbook?.title ? (
                <p className="mt-2 text-sm font-medium">{playbook.title}</p>
              ) : null}
              <p className="mt-2 text-sm opacity-70">{expl.headline}</p>
              <dl className="mt-3 grid gap-2 text-sm sm:grid-cols-2">
                <div>
                  <dt className="text-xs uppercase text-base-content/60">
                    Window start (UTC)
                  </dt>
                  <dd className="font-mono">{formatUtc(anomaly.window_start)}</dd>
                </div>
                <div>
                  <dt className="text-xs uppercase text-base-content/60">
                    Window end (UTC)
                  </dt>
                  <dd className="font-mono">{formatUtc(anomaly.window_end)}</dd>
                </div>
              </dl>
              {expl.spectral ? (
                <p className="mt-2 text-sm opacity-80">
                  Legs:{" "}
                  {expl.spectral.crossing_legs.length
                    ? expl.spectral.crossing_legs.join(", ")
                    : "none"}
                  {expl.spectral.dominant_period_hours != null
                    ? ` · window period ~${formatMaybeNumber(expl.spectral.dominant_period_hours, 1)} h`
                    : null}
                </p>
              ) : null}
              {expl.gap?.possible_gap ? (
                <p className="mt-2 text-sm">
                  Possible log gap:{" "}
                  {formatMaybeNumber(expl.gap.zero_fraction, 2)} of buckets in
                  this window are zero.
                </p>
              ) : null}
              {expl.ml?.ensemble?.votes ? (
                <p className="mt-2 text-sm opacity-80">
                  Ensemble votes
                  {expl.ml.ensemble.fusion
                    ? ` (${expl.ml.ensemble.fusion})`
                    : null}
                  :{" "}
                  {Object.entries(expl.ml.ensemble.votes)
                    .map(
                      ([name, voted]) =>
                        `${name}=${voted ? "flag" : "clear"}`,
                    )
                    .join(", ")}
                </p>
              ) : null}
              {expl.ml?.top_templates && expl.ml.top_templates.length > 0 ? (
                <div className="mt-3">
                  <h3 className="text-sm font-medium">
                    Top contributing templates
                    {expl.ml.model_type ? (
                      <span className="ml-2 font-normal text-base-content/60">
                        ({expl.ml.model_type})
                      </span>
                    ) : null}
                  </h3>
                  <ul className="mt-1 list-disc pl-5 text-sm">
                    {expl.ml.top_templates.map((row) => (
                      <li key={row.template_id} className="font-mono">
                        {row.template_id}
                        {row.contribution != null
                          ? ` · contrib ${formatMaybeNumber(row.contribution, 2)}`
                          : null}
                        {row.event_count
                          ? ` · count ${row.event_count}`
                          : null}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
              <p className="mt-2 text-sm opacity-80">{sourcesLine(anomaly)}</p>
              {playbook ? (
                <div className="mt-3">
                  <h3 className="text-sm font-medium">
                    Playbook{" "}
                    <LinkDocsMore
                      href={docsPlaybooksHref()}
                      className="link link-primary ml-1 text-xs font-normal"
                    >
                      catalogue
                    </LinkDocsMore>
                  </h3>
                  <p className="text-sm opacity-80">{playbook.hint}</p>
                  {playbook.actions.length ? (
                    <ul className="mt-1 list-disc pl-5 text-sm">
                      {playbook.actions.map((action) => (
                        <li key={action}>{action}</li>
                      ))}
                    </ul>
                  ) : null}
                </div>
              ) : null}
              <p className="mt-4">
                <Link className="btn btn-sm btn-primary" href={eventsHref}>
                  View events in this window
                </Link>
              </p>
              <FormAnalystAction
                incidentId={incident.incident_id}
                anomalyId={anomaly.anomaly_id}
                defaultOperatorLabel={defaultOperatorLabel}
                mode="anomaly"
                defaultAction={
                  disposition === "dismissed" ? "reopen" : "dismiss"
                }
              />
            </article>
          );
        })
      )}
    </section>
  );
}
