import { NavPagination } from "@/components/layout/NavPagination";
import { EVENT_PAGE_SIZE, formatFields, formatUtc } from "@/lib/format";
import type { TimelineEvent } from "@/lib/types";

type TableEntityTimelineProps = {
  items: TimelineEvent[];
  newestFirst: boolean;
  total?: number;
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

export function TableEntityTimeline({
  items,
  newestFirst,
  total,
  offset = 0,
  hrefForPage,
}: TableEntityTimelineProps) {
  const resolvedTotal = total ?? items.length;
  const page = Math.floor(offset / EVENT_PAGE_SIZE) + 1;
  const showingFrom = items.length ? offset + 1 : 0;
  const showingTo = offset + items.length;
  const totalPages = resolvedTotal
    ? Math.max(1, Math.ceil(resolvedTotal / EVENT_PAGE_SIZE))
    : 1;

  return (
    <section className="flex flex-col gap-3">
      <h2 className="text-lg font-semibold">Event timeline (parsed_events)</h2>
      {items.length === 0 ? (
        <div className="alert">
          <span>No parsed_events for this entity in the selected window.</span>
        </div>
      ) : (
        <>
          <p className="text-sm opacity-70">
            {newestFirst ? "newest first · " : null}
            showing {showingFrom}–{showingTo} of {resolvedTotal}
          </p>
          <div className="fft-paper-panel overflow-x-auto">
            <table className="table table-sm">
              <thead>
                <tr>
                  <th>Timestamp (UTC)</th>
                  <th>Source</th>
                  <th>Template</th>
                  <th>Fields</th>
                  <th>Related anomalies</th>
                </tr>
              </thead>
              <tbody>
                {items.map((event) => (
                  <tr key={event.event_id}>
                    <td className="font-mono text-sm">
                      {formatUtc(event.event_timestamp)}
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
                      <div className="font-mono">
                        {event.template_string || event.template_id || "—"}
                      </div>
                      {event.template_id && event.template_string ? (
                        <div className="font-mono text-xs text-base-content/60">
                          {event.template_id}
                        </div>
                      ) : null}
                    </td>
                    <td className="max-w-md text-sm">
                      <FieldsCell fields={event.raw_fields} />
                    </td>
                    <td className="font-mono text-sm">
                      {event.related_anomaly_ids.length
                        ? event.related_anomaly_ids.join(", ")
                        : "—"}
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
