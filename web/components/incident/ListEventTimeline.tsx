import Link from "next/link";
import { formatUtc } from "@/lib/format";
import { entityEventsHref } from "@/lib/hrefs";
import type { IncidentTimelineEvent } from "@/lib/types";

type ListEventTimelineProps = {
  items: IncidentTimelineEvent[];
  total: number;
  entityId: string;
  start?: string | null;
  end?: string | null;
  viewAllHref?: string;
};

export function ListEventTimeline({
  items,
  total,
  entityId,
  start,
  end,
  viewAllHref,
}: ListEventTimelineProps) {
  return (
    <section className="flex flex-col gap-3">
      <h2 className="text-lg font-semibold">Event timeline</h2>
      <p className="text-sm opacity-70">Timestamps (UTC)</p>
      {items.length === 0 ? (
        <div className="alert">
          <span>No correlation_edges for this incident’s anomalies.</span>
        </div>
      ) : (
        <>
          <p className="text-sm opacity-70">
            showing {items.length} of {total} ·{" "}
            <Link className="link" href={entityEventsHref(entityId, start, end)}>
              entity events
            </Link>
            {viewAllHref ? (
              <>
                {" · "}
                <Link className="link" href={viewAllHref}>
                  View all {total} events
                </Link>
              </>
            ) : null}
          </p>
          <ol className="relative ml-2 border-l border-base-300">
            {items.map((event, index) => (
              <li
                key={`${event.event_id ?? "edge"}-${index}`}
                className="relative mb-4 ml-4"
              >
                <span className="absolute -left-1.5 mt-1.5 h-3 w-3 rounded-full bg-primary" />
                <p className="font-mono text-sm">
                  {formatUtc(event.event_timestamp)}
                </p>
                <p className="mt-1 flex flex-wrap gap-2">
                  <span className="badge badge-sm">{event.relation_type}</span>
                  {event.log_source ? (
                    <span className="badge badge-outline badge-sm">
                      {event.log_source}
                    </span>
                  ) : null}
                </p>
                <p className="mt-1 text-sm">
                  {event.template_string || event.snippet || "—"}
                </p>
              </li>
            ))}
          </ol>
        </>
      )}
    </section>
  );
}
