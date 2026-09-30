import { AlertApiDown } from "@/components/feedback/AlertApiDown";
import { AlertWarehouseBusy } from "@/components/feedback/AlertWarehouseBusy";
import { CardAnalystActions } from "@/components/incident/CardAnalystActions";
import { CardIncidentReports } from "@/components/incident/CardIncidentReports";
import { CardIncidentWhy } from "@/components/incident/CardIncidentWhy";
import { ListEventTimeline } from "@/components/incident/ListEventTimeline";
import { TableAnomalyList } from "@/components/incident/TableAnomalyList";
import {
  fetchIncident,
  fetchIncidentTimeline,
  fetchReports,
  fetchUiPolicy,
} from "@/lib/api";
import { incidentEventsHref, incidentHref } from "@/lib/hrefs";
import { reportsForIncident } from "@/lib/reports";

type IncidentOverviewPanelProps = {
  incidentId: string;
};

export async function IncidentOverviewPanel({
  incidentId,
}: IncidentOverviewPanelProps) {
  const retryHref = incidentHref(incidentId);

  const [incidentResult, timelineResult, reportsResult, policyResult] =
    await Promise.all([
      fetchIncident(incidentId),
      fetchIncidentTimeline(incidentId, { limit: 10, offset: 0 }),
      fetchReports({ limit: 500 }),
      fetchUiPolicy(),
    ]);

  if (!incidentResult.ok) {
    if (incidentResult.reason === "warehouse_busy" || incidentResult.reason === "warehouse_missing") {
      return <AlertWarehouseBusy retryHref={retryHref} />;
    }
    return <AlertApiDown />;
  }

  const incident = incidentResult.data;
  const actions = incident.actions ?? [];
  const defaultOperatorLabel = policyResult.ok
    ? policyResult.data.operator_label
    : "local";
  const timelineItems = timelineResult.ok ? timelineResult.data.items : [];
  const timelineTotal = timelineResult.ok
    ? timelineResult.data.total
    : timelineItems.length;
  const incidentReports = reportsResult.ok
    ? reportsForIncident(reportsResult.data.items, incident.incident_id)
    : [];

  return (
    <div className="flex flex-col gap-8">
      <CardIncidentWhy
        incident={incident}
        defaultOperatorLabel={defaultOperatorLabel}
      />
      <TableAnomalyList
        anomalies={incident.anomalies}
        total={incident.anomalies_total}
        actions={actions}
      />
      {timelineResult.ok ? (
        <ListEventTimeline
          items={timelineItems}
          total={timelineTotal}
          entityId={incident.entity_id}
          start={incident.start_time}
          end={incident.end_time}
          viewAllHref={incidentEventsHref(incidentId)}
        />
      ) : (
        <div role="alert" className="alert alert-warning">
          <span>
            Timeline could not be loaded. Why-flagged above is still from the
            incident payload.
          </span>
        </div>
      )}
      <CardAnalystActions
        incidentId={incident.incident_id}
        actions={actions}
        defaultOperatorLabel={defaultOperatorLabel}
      />
      <CardIncidentReports
        reports={incidentReports}
        incidentId={incident.incident_id}
      />
    </div>
  );
}
