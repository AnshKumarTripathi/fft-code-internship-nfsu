import Link from "next/link";
import { NavPagination } from "@/components/layout/NavPagination";
import { displayValue, EVENT_PAGE_SIZE, formatFields, formatUtc } from "@/lib/format";
import { entityEventsHref } from "@/lib/hrefs";
import type { IncidentTimelineEvent } from "@/lib/types";

type TableEventTimelineProps = {
  items: IncidentTimelineEvent[];
  total: number;
  entityId: string;
  start?: string | null;
  end?: string | null;
  offset?: number;
  hrefForPage?: (page: number) => string;
};

function FieldsCell({ fields }: { fields: Record<string, unknown> }) {
  const text = formatFields(fields);
  if (text === "—") {
    return "—";
  }
  return (
    <details>
      <summary className="cursor-pointer text-sm opacity-70">fields</summary>
      <pre className="mt-1 max-w-md whitespace-pre-wrap font-mono text-xs">
        {text}
      </pre>
    </details>
  );
}

export function TableEventTimeline({
  items,
  total,
  entityId,
  start,
  end,
  offset = 0,
  hrefForPage,
}: TableEventTimelineProps) {
  const page = Math.floor(offset / EVENT_PAGE_SIZE) + 1;
  const showingFrom = items.length ? offset + 1 : 0;
  const showingTo = offset + items.length;
  const totalPages = total ? Math.max(1, Math.ceil(total / EVENT_PAGE_SIZE)) : 1;

  return (
    <section className="flex flex-col gap-3">
      <h2 className="text-lg font-semibold">Event timeline</h2>
      {items.length === 0 ? (
        <div className="alert">
          <span>No correlation_edges for this incident’s anomalies.</span>
        </div>
      ) : (
        <>
          <p className="text-sm opacity-70">
            showing {showingFrom}–{showingTo} of {total} ·{" "}
            <Link className="link" href={entityEventsHref(entityId, start, end)}>
              entity events
            </Link>
          </p>
          <div className="fft-paper-panel overflow-x-auto">
            <table className="table table-sm">
              <thead>
                <tr>
                  <th>Timestamp (UTC)</th>
                  <th>Relation</th>
                  <th>Source</th>
                  <th>Template</th>
                  <th>Fields</th>
                  <th>Anomaly</th>
                </tr>
              </thead>
              <tbody>
                {items.map((event, index) => (
                  <tr key={`${event.event_id ?? "edge"}-${index}`}>
                    <td className="font-mono text-sm">
                      {formatUtc(event.event_timestamp)}
                    </td>
                    <td className="font-mono text-sm">
                      {displayValue(event.relation_type)}
                    </td>
                    <td>
                      {event.log_source ? (
                        <span className="badge badge-outline badge-sm">
                          {event.log_source}
                        </span>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td className="max-w-md text-sm">
                      {event.template_string || event.snippet || "—"}
                    </td>
                    <td className="max-w-md text-sm">
                      <FieldsCell fields={event.raw_fields} />
                    </td>
                    <td className="font-mono text-sm">
                      {event.dst_anomaly_id}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {hrefForPage ? (
            <NavPagination
              page={page}
              totalPages={totalPages}
              hrefForPage={hrefForPage}
              label="Event pages"
            />
          ) : null}
        </>
      )}
    </section>
  );
}
