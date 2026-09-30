import Link from "next/link";
import { AlertApiDown } from "@/components/feedback/AlertApiDown";
import { AlertWarehouseBusy } from "@/components/feedback/AlertWarehouseBusy";
import { TableCorrelationEdges } from "@/components/incident/TableCorrelationEdges";
import { TableEventTimeline } from "@/components/incident/TableEventTimeline";
import {
  fetchIncident,
  fetchIncidentEdges,
  fetchIncidentTimeline,
} from "@/lib/api";
import { EVENT_PAGE_SIZE, parsePage } from "@/lib/format";
import { incidentEventsHref, incidentHref } from "@/lib/hrefs";

type IncidentEventsPanelProps = {
  incidentId: string;
  query: { page?: string; step?: string };
};

export async function IncidentEventsPanel({
  incidentId,
  query,
}: IncidentEventsPanelProps) {
  const page = parsePage(query.page);
  const step = query.step === "edges" ? "edges" : "timeline";
  const offset = (page - 1) * EVENT_PAGE_SIZE;
  const retryHref = incidentEventsHref(incidentId, page, step);

  const incidentResult = await fetchIncident(incidentId);
  if (!incidentResult.ok) {
    if (incidentResult.reason === "warehouse_busy" || incidentResult.reason === "warehouse_missing") {
      return <AlertWarehouseBusy retryHref={retryHref} />;
    }
    return <AlertApiDown />;
  }

  const incident = incidentResult.data;

  const [timelineResult, edgesResult] = await Promise.all([
    step === "timeline"
      ? fetchIncidentTimeline(incidentId, {
          limit: EVENT_PAGE_SIZE,
          offset,
        })
      : Promise.resolve(null),
    step === "edges"
      ? fetchIncidentEdges(incidentId, { limit: EVENT_PAGE_SIZE, offset })
      : Promise.resolve(null),
  ]);

  if (timelineResult && !timelineResult.ok) {
    if (timelineResult.reason === "warehouse_busy" || timelineResult.reason === "warehouse_missing") {
      return <AlertWarehouseBusy retryHref={retryHref} />;
    }
    return <AlertApiDown />;
  }
  if (edgesResult && !edgesResult.ok) {
    if (edgesResult.reason === "warehouse_busy" || edgesResult.reason === "warehouse_missing") {
      return <AlertWarehouseBusy retryHref={retryHref} />;
    }
    return <AlertApiDown />;
  }

  const tabClass = (active: boolean) =>
    active ? "tab tab-active" : "tab";

  return (
    <div className="flex flex-col gap-6">
      <div className="tabs tabs-border" role="tablist" aria-label="Event step">
        <Link
          role="tab"
          className={tabClass(step === "timeline")}
          href={incidentEventsHref(incidentId, 1, "timeline")}
          aria-selected={step === "timeline"}
        >
          Timeline
        </Link>
        <Link
          role="tab"
          className={tabClass(step === "edges")}
          href={incidentEventsHref(incidentId, 1, "edges")}
          aria-selected={step === "edges"}
        >
          Edges
        </Link>
      </div>

      {step === "timeline" && timelineResult?.ok ? (
        <TableEventTimeline
          items={timelineResult.data.items}
          total={timelineResult.data.total}
          entityId={incident.entity_id}
          start={incident.start_time}
          end={incident.end_time}
          offset={timelineResult.data.offset}
          hrefForPage={(nextPage) =>
            incidentEventsHref(incidentId, nextPage, "timeline")
          }
        />
      ) : null}

      {step === "edges" && edgesResult?.ok ? (
        <TableCorrelationEdges
          items={edgesResult.data.items}
          counts={incident.edge_counts}
          total={edgesResult.data.total}
          offset={edgesResult.data.offset}
          hrefForPage={(nextPage) =>
            incidentEventsHref(incidentId, nextPage, "edges")
          }
        />
      ) : null}

      <p className="text-sm opacity-70">
        Overview:{" "}
        <Link className="link" href={incidentHref(incidentId)}>
          incident summary
        </Link>
      </p>
    </div>
  );
}
