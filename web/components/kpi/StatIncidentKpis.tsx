import Link from "next/link";
import { DetailsDetectorGlossary } from "@/components/feedback/DetailsDetectorGlossary";
import { LinkDocsMore } from "@/components/docs/LinkDocsMore";
import {
  DETECTOR_ORDER,
  KPI_MEANINGS,
  detectorLabel,
  detectorMeaning,
  detectorRole,
} from "@/lib/detectors";
import { docsKpiHref } from "@/lib/docs-links";
import { formatUtc } from "@/lib/format";
import {
  incidentListHref,
  runsHref,
  type IncidentListHrefParams,
} from "@/lib/hrefs";
import type { IncidentKpis } from "@/lib/types";

export type IncidentListFilterState = {
  severity?: string;
  entity_id?: string;
  q?: string;
  start_after?: string;
  end_before?: string;
  detector?: string;
  min_detectors?: number;
  disposition?: string;
  sort?: string;
  order?: string;
};

type StatIncidentKpisProps = {
  kpis: IncidentKpis;
  /** Current list filters so KPI clicks preserve disposition and siblings. */
  filters?: IncidentListFilterState;
  /** Override list href builder (analysis-scoped triage). */
  listHref?: (params: IncidentListHrefParams) => string;
  /** Optional caption under the KPI strip. */
  caption?: string;
};

function severityHref(
  severity: string | undefined,
  filters: IncidentListFilterState,
  listHref: (params: IncidentListHrefParams) => string,
): string {
  return listHref({
    ...filters,
    severity,
    page: undefined,
  });
}

function detectorHref(
  detector: string,
  filters: IncidentListFilterState,
  listHref: (params: IncidentListHrefParams) => string,
): string {
  return listHref({
    ...filters,
    detector,
    page: undefined,
  });
}

export function StatIncidentKpis({
  kpis,
  filters = {},
  listHref = incidentListHref,
  caption = "KPIs are warehouse-wide (not limited by the table filters below).",
}: StatIncidentKpisProps) {
  const detectorCounts = kpis.detector_counts ?? {};
  const logSources = kpis.log_source_counts ?? [];
  const baseFilters: IncidentListFilterState = {
    ...filters,
    disposition: filters.disposition ?? "open",
  };

  return (
    <div className="flex flex-col gap-4">
      <p className="text-xs text-base-content/60">
        {caption}{" "}
        <LinkDocsMore href={docsKpiHref()} className="link link-primary text-xs">
          KPI dictionary
        </LinkDocsMore>
      </p>
      <DetailsDetectorGlossary />
      <section className="fft-paper-panel stats stats-vertical w-full sm:stats-horizontal">
        <div className="stat">
          <div className="stat-title" title={KPI_MEANINGS.incidents}>
            Incidents
          </div>
          <div className="stat-value text-primary">
            <Link
              className="link link-hover"
              href={severityHref(
                undefined,
                {
                  ...baseFilters,
                  severity: undefined,
                },
                listHref,
              )}
              title={KPI_MEANINGS.incidents}
            >
              {kpis.total}
            </Link>
          </div>
        </div>
        <div className="stat">
          <div className="stat-title" title={KPI_MEANINGS.severity}>
            Critical
          </div>
          <div className="stat-value text-error">
            <Link
              className="link link-hover"
              href={severityHref("critical", baseFilters, listHref)}
              title={KPI_MEANINGS.severity}
            >
              {kpis.critical}
            </Link>
          </div>
        </div>
        <div className="stat">
          <div className="stat-title" title={KPI_MEANINGS.severity}>
            High
          </div>
          <div className="stat-value text-warning">
            <Link
              className="link link-hover"
              href={severityHref("high", baseFilters, listHref)}
              title={KPI_MEANINGS.severity}
            >
              {kpis.high}
            </Link>
          </div>
        </div>
        <div className="stat">
          <div className="stat-title" title={KPI_MEANINGS.severity}>
            Medium
          </div>
          <div className="stat-value">
            <Link
              className="link link-hover"
              href={severityHref("medium", baseFilters, listHref)}
              title={KPI_MEANINGS.severity}
            >
              {kpis.medium}
            </Link>
          </div>
        </div>
        <div className="stat">
          <div className="stat-title" title={KPI_MEANINGS.severity}>
            Low
          </div>
          <div className="stat-value">
            <Link
              className="link link-hover"
              href={severityHref("low", baseFilters, listHref)}
              title={KPI_MEANINGS.severity}
            >
              {kpis.low}
            </Link>
          </div>
        </div>
      </section>

      <section
        className="fft-paper-panel flex flex-wrap items-center gap-3 bg-base-200/40 px-4 py-3 text-sm"
        aria-label="Pipeline status"
      >
        <span className="text-xs uppercase text-base-content/60">Pipeline</span>
        <span>
          Last correlate (UTC):{" "}
          <span className="fft-mono-meta">
            {kpis.last_correlate_at
              ? formatUtc(kpis.last_correlate_at)
              : "never"}
          </span>
        </span>
        <span className="opacity-40" aria-hidden>
          ·
        </span>
        <span>
          Last report (UTC):{" "}
          <span className="fft-mono-meta">
            {kpis.last_report_at ? formatUtc(kpis.last_report_at) : "never"}
          </span>
        </span>
        <Link className="link text-sm" href={runsHref()}>
          View runs
        </Link>
      </section>

      <div className="flex flex-col gap-2">
        <p className="text-xs uppercase text-base-content/60" title={KPI_MEANINGS.detectors}>
          Detectors
        </p>
        <p className="text-xs text-base-content/60">{KPI_MEANINGS.detectors}</p>
        <p className="flex flex-wrap gap-2">
          {DETECTOR_ORDER.map((detector) => (
            <Link
              key={detector}
              className="badge badge-outline hover:badge-primary"
              href={detectorHref(detector, baseFilters, listHref)}
              title={detectorMeaning(detector) || detectorLabel(detector)}
            >
              {detectorRole(detector)} {detectorCounts[detector] ?? 0}
            </Link>
          ))}
        </p>
      </div>
      {logSources.length ? (
        <div className="flex flex-col gap-2">
          <p className="text-xs uppercase text-base-content/60">
            Log sources (counts only — no list filter yet)
          </p>
          <p className="flex flex-wrap gap-2">
            {logSources.map((row) => (
              <span key={row.log_source} className="badge badge-ghost">
                {row.log_source} {row.count}
              </span>
            ))}
          </p>
        </div>
      ) : null}
    </div>
  );
}
