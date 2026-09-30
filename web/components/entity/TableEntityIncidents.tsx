import Link from "next/link";
import { formatUtc, severityBadgeClass, snippet } from "@/lib/format";
import { incidentHref } from "@/lib/hrefs";
import type { IncidentItem } from "@/lib/types";

type TableEntityIncidentsProps = {
  items: IncidentItem[];
};

export function TableEntityIncidents({ items }: TableEntityIncidentsProps) {
  return (
    <section className="flex flex-col gap-3">
      <h2 className="text-lg font-semibold">Incidents</h2>
      {items.length === 0 ? (
        <div className="alert">
          <span>No incidents include this entity.</span>
        </div>
      ) : (
        <div className="fft-paper-panel overflow-x-auto">
          <table className="table table-sm">
            <thead>
              <tr>
                <th>Incident</th>
                <th>Severity</th>
                <th>Start (UTC)</th>
                <th>End (UTC)</th>
                <th>Summary</th>
              </tr>
            </thead>
            <tbody>
              {items.map((incident) => (
                <tr key={incident.incident_id} className="hover">
                  <td>
                    <Link
                      className="link font-mono text-sm"
                      href={incidentHref(incident.incident_id)}
                    >
                      {incident.incident_id}
                    </Link>
                  </td>
                  <td>
                    <span className={severityBadgeClass(incident.severity)}>
                      {incident.severity}
                    </span>
                  </td>
                  <td className="font-mono text-sm">
                    {formatUtc(incident.start_time)}
                  </td>
                  <td className="font-mono text-sm">
                    {formatUtc(incident.end_time)}
                  </td>
                  <td className="max-w-md truncate" title={incident.summary_text ?? ""}>
                    {snippet(incident.summary_text)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
