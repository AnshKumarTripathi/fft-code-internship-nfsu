import Link from "next/link";
import { AlertEmptyFiltered } from "@/components/feedback/AlertEmptyFiltered";
import { AlertEmptyIncidents } from "@/components/feedback/AlertEmptyIncidents";
import { AlertPipelineNotRun } from "@/components/feedback/AlertPipelineNotRun";
import { NavPagination } from "@/components/layout/NavPagination";
import { DETECTOR_ORDER, detectorLabel, detectorMeaning, detectorRole, incidentDetectorTeaser } from "@/lib/detectors";
import {
  INCIDENT_DISPOSITIONS,
  INCIDENT_PAGE_SIZE,
  INCIDENT_SORTS,
  SEVERITIES,
  formatUtc,
  severityBadgeClass,
  shortId,
  snippet,
  toDatetimeLocalValue,
} from "@/lib/format";
import { entityHref, incidentHref, incidentListHref } from "@/lib/hrefs";
import type { IncidentListHrefParams } from "@/lib/hrefs";
import type { IncidentItem } from "@/lib/types";

type TableIncidentListProps = {
  items: IncidentItem[];
  total: number;
  offset: number;
  severity: string;
  entityId: string;
  q: string;
  startAfter: string;
  endBefore: string;
  detector: string;
  minDetectors: number | undefined;
  disposition: string;
  sort: string;
  order: string;
  warehouseEmpty: boolean;
  pipelineRan: boolean;
  listHref?: (params: IncidentListHrefParams) => string;
  /** Form GET action for filter submit (default `/incidents`). */
  formAction?: string;
};

function filterParams(props: {
  severity: string;
  entityId: string;
  q: string;
  startAfter: string;
  endBefore: string;
  detector: string;
  minDetectors: number | undefined;
  disposition: string;
  sort: string;
  order: string;
}): {
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
} {
  return {
    severity: props.severity || undefined,
    entity_id: props.entityId || undefined,
    q: props.q || undefined,
    start_after: props.startAfter || undefined,
    end_before: props.endBefore || undefined,
    detector: props.detector || undefined,
    min_detectors: props.minDetectors,
    disposition: props.disposition || undefined,
    sort: props.sort && props.sort !== "severity" ? props.sort : undefined,
    order: props.order === "asc" ? props.order : undefined,
  };
}

export function TableIncidentList({
  items,
  total,
  offset,
  severity,
  entityId,
  q,
  startAfter,
  endBefore,
  detector,
  minDetectors,
  disposition,
  sort,
  order,
  warehouseEmpty,
  pipelineRan,
  listHref = incidentListHref,
  formAction = "/incidents",
}: TableIncidentListProps) {
  const page = Math.floor(offset / INCIDENT_PAGE_SIZE) + 1;
  const showingFrom = items.length ? offset + 1 : 0;
  const showingTo = offset + items.length;
  const totalPages = total
    ? Math.max(1, Math.ceil(total / INCIDENT_PAGE_SIZE))
    : 1;
  const filters = filterParams({
    severity,
    entityId,
    q,
    startAfter,
    endBefore,
    detector,
    minDetectors,
    disposition,
    sort,
    order,
  });
  const isOpenQueue = disposition === "open";
  const showAllHref = listHref({
    ...filters,
    disposition: "any",
    page: undefined,
  });
  const openQueueHref = listHref({
    ...filters,
    disposition: "open",
    page: undefined,
  });
  const dismissedHref = listHref({
    ...filters,
    disposition: "dismissed",
    page: undefined,
  });

  return (
    <section className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        {isOpenQueue ? (
          <span className="badge badge-primary badge-sm">
            Needs review — showing open only
          </span>
        ) : disposition === "dismissed" ? (
          <span className="badge badge-sm">Showing dismissed</span>
        ) : (
          <span className="badge badge-ghost badge-sm">Showing all</span>
        )}
        <Link className="btn btn-xs btn-ghost" href={openQueueHref}>
          Open queue
        </Link>
        <Link className="btn btn-xs btn-ghost" href={dismissedHref}>
          Dismissed
        </Link>
        <Link className="btn btn-xs btn-ghost" href={showAllHref}>
          Show all
        </Link>
      </div>
      <form
        className="flex flex-wrap items-end gap-3"
        method="get"
        action={formAction}
      >
        <label className="form-control w-40">
          <span className="label-text mb-1">Severity</span>
          <select
            id="severity"
            name="severity"
            className="select select-bordered select-sm"
            defaultValue={severity}
            suppressHydrationWarning
          >
            <option value="">Any</option>
            {SEVERITIES.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </label>
        <label className="form-control w-40">
          <span className="label-text mb-1">Detector</span>
          <select
            id="detector"
            name="detector"
            className="select select-bordered select-sm"
            defaultValue={detector}
            suppressHydrationWarning
          >
            <option value="">Any</option>
                {DETECTOR_ORDER.map((value) => (
                  <option key={value} value={value}>
                    {detectorRole(value)} ({detectorLabel(value)})
                  </option>
                ))}
          </select>
        </label>
        <label className="form-control w-36">
          <span className="label-text mb-1">Min detectors</span>
          <input
            id="min_detectors"
            type="number"
            name="min_detectors"
            min={1}
            className="input input-bordered input-sm"
            defaultValue={minDetectors ?? ""}
            placeholder="1+"
            suppressHydrationWarning
          />
        </label>
        <label className="form-control w-40">
          <span className="label-text mb-1">Disposition</span>
          <select
            id="disposition"
            name="disposition"
            className="select select-bordered select-sm"
            defaultValue={disposition || "open"}
            suppressHydrationWarning
          >
            {INCIDENT_DISPOSITIONS.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </label>
        <label className="form-control w-44">
          <span className="label-text mb-1">Start after (UTC)</span>
          <input
            id="start_after"
            type="datetime-local"
            name="start_after"
            className="input input-bordered input-sm"
            defaultValue={toDatetimeLocalValue(startAfter)}
            suppressHydrationWarning
          />
        </label>
        <label className="form-control w-44">
          <span className="label-text mb-1">End before (UTC)</span>
          <input
            id="end_before"
            type="datetime-local"
            name="end_before"
            className="input input-bordered input-sm"
            defaultValue={toDatetimeLocalValue(endBefore)}
            suppressHydrationWarning
          />
        </label>
        <label className="form-control min-w-48 flex-1">
          <span className="label-text mb-1">Entity ID</span>
          <input
            id="entity_id"
            type="text"
            name="entity_id"
            className="input input-bordered input-sm"
            defaultValue={entityId}
            placeholder="root or 192.0.2.1"
            suppressHydrationWarning
          />
        </label>
        <label className="form-control min-w-48 flex-1">
          <span className="label-text mb-1">Summary</span>
          <input
            id="q"
            type="text"
            name="q"
            className="input input-bordered input-sm"
            defaultValue={q}
            placeholder="search summary_text"
            suppressHydrationWarning
          />
        </label>
        <label className="form-control w-44">
          <span className="label-text mb-1">Sort</span>
          <select
            id="sort"
            name="sort"
            className="select select-bordered select-sm"
            defaultValue={sort || "severity"}
            suppressHydrationWarning
          >
            {INCIDENT_SORTS.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </label>
        <label className="form-control w-32">
          <span className="label-text mb-1">Order</span>
          <select
            id="order"
            name="order"
            className="select select-bordered select-sm"
            defaultValue={order || "desc"}
            suppressHydrationWarning
          >
            <option value="desc">desc</option>
            <option value="asc">asc</option>
          </select>
        </label>
        <button
          className="btn btn-sm btn-primary"
          type="submit"
          suppressHydrationWarning
        >
          Apply
        </button>
        <Link
          className="btn btn-sm btn-ghost"
          href={listHref({ disposition: "open" })}
        >
          Clear
        </Link>
      </form>
      <p className="text-xs text-base-content/60">
        Default queue is open (needs review). Disposition uses the
        all-anomalies rule: dismissed only when every contributing
        anomaly&apos;s latest dismiss/reopen action is dismiss. Datetimes are
        treated as UTC.
      </p>

      {items.length === 0 ? (
        warehouseEmpty ? (
          pipelineRan ? (
            <AlertEmptyIncidents />
          ) : (
            <AlertPipelineNotRun />
          )
        ) : (
          <AlertEmptyFiltered />
        )
      ) : (
        <>
          <p className="text-sm opacity-70">
            Showing {showingFrom}–{showingTo} of {total}
          </p>
          <div className="fft-paper-panel overflow-x-auto">
            <table className="table table-sm">
              <thead>
                <tr className="text-xs uppercase tracking-wide text-base-content/60">
                  <th>Severity</th>
                  <th>Summary</th>
                  <th>Entity</th>
                  <th>Detectors</th>
                  <th>Anomalies</th>
                  <th>Start (UTC)</th>
                  <th>End (UTC)</th>
                  <th>Meaning</th>
                  <th>Id</th>
                </tr>
              </thead>
              <tbody>
                {items.map((incident) => (
                  <tr key={incident.incident_id} className="hover">
                    <td>
                      <span className={severityBadgeClass(incident.severity)}>
                        {incident.severity}
                      </span>
                    </td>
                    <td>
                      <div className="flex max-w-md flex-col gap-1">
                        <Link
                          className="link text-sm font-medium"
                          href={incidentHref(incident.incident_id)}
                          title={incident.summary_text ?? ""}
                        >
                          {snippet(incident.summary_text) || "Open incident"}
                        </Link>
                        <Link
                          className="link text-xs text-base-content/70"
                          href={incidentHref(incident.incident_id)}
                        >
                          Why flagged
                        </Link>
                      </div>
                    </td>
                    <td>
                      <Link
                        className="link text-sm"
                        href={entityHref(incident.entity_id)}
                      >
                        {incident.entity_id}
                      </Link>
                    </td>
                    <td>
                      <span className="flex flex-wrap gap-1">
                        {(incident.detector_set ?? []).map((value) => (
                          <span
                            key={value}
                            className="badge badge-outline badge-sm"
                            title={detectorMeaning(value) || detectorLabel(value)}
                          >
                            {detectorRole(value)}
                          </span>
                        ))}
                      </span>
                    </td>
                    <td className="text-sm">
                      {incident.anomaly_count ??
                        incident.contributing_anomaly_ids.length}
                    </td>
                    <td className="fft-mono-meta">
                      {formatUtc(incident.start_time)}
                    </td>
                    <td className="fft-mono-meta">
                      {formatUtc(incident.end_time)}
                    </td>
                    <td
                      className="max-w-xs text-sm text-base-content/80"
                      title={incidentDetectorTeaser(incident.detector_set)}
                    >
                      {incidentDetectorTeaser(incident.detector_set)}
                    </td>
                    <td>
                      <Link
                        className="fft-mono-meta link"
                        href={incidentHref(incident.incident_id)}
                        title={incident.incident_id}
                      >
                        {shortId(incident.incident_id)}
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <NavPagination
            page={page}
            totalPages={totalPages}
            hrefForPage={(next) => listHref({ ...filters, page: next })}
            label="Incident pages"
          />
        </>
      )}
    </section>
  );
}
