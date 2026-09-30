import { NavPagination } from "@/components/layout/NavPagination";
import { displayValue, EVENT_PAGE_SIZE } from "@/lib/format";
import type { IncidentEdgeItem } from "@/lib/types";

type TableCorrelationEdgesProps = {
  items: IncidentEdgeItem[];
  counts?: Record<string, number>;
  total?: number;
  offset?: number;
  hrefForPage?: (page: number) => string;
};

const EDGE_ORDER = ["precedes", "same_session", "same_ip", "same_host"];

export function TableCorrelationEdges({
  items,
  counts,
  total,
  offset = 0,
  hrefForPage,
}: TableCorrelationEdgesProps) {
  const resolvedCounts = counts ?? {};
  const hasCounts =
    EDGE_ORDER.some((key) => (resolvedCounts[key] ?? 0) > 0) ||
    Object.keys(resolvedCounts).length > 0;
  const resolvedTotal = total ?? items.length;
  const page = Math.floor(offset / EVENT_PAGE_SIZE) + 1;
  const showingFrom = items.length ? offset + 1 : 0;
  const showingTo = offset + items.length;
  const totalPages = resolvedTotal
    ? Math.max(1, Math.ceil(resolvedTotal / EVENT_PAGE_SIZE))
    : 1;

  return (
    <section className="flex flex-col gap-3">
      <h2 className="text-lg font-semibold">Correlation</h2>
      {hasCounts ? (
        <div className="fft-paper-panel overflow-x-auto">
          <table className="table table-sm w-auto">
            <thead>
              <tr>
                <th>Relation</th>
                <th>Count</th>
              </tr>
            </thead>
            <tbody>
              {EDGE_ORDER.map((relation) => (
                <tr key={relation}>
                  <td className="font-mono text-sm">{relation}</td>
                  <td className="font-mono text-sm">
                    {resolvedCounts[relation] ?? 0}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {items.length === 0 ? (
        <div className="alert">
          <span>No correlation edges to list.</span>
        </div>
      ) : (
        <>
          {hrefForPage ? (
            <p className="text-sm opacity-70">
              showing {showingFrom}–{showingTo} of {resolvedTotal}
            </p>
          ) : null}
          <div className="fft-paper-panel overflow-x-auto">
            <table className="table table-sm">
              <thead>
                <tr>
                  <th>Edge</th>
                  <th>Event</th>
                  <th>Anomaly</th>
                  <th>Relation</th>
                  <th>Session</th>
                </tr>
              </thead>
              <tbody>
                {items.map((edge) => (
                  <tr key={edge.edge_id}>
                    <td className="font-mono text-sm">{edge.edge_id}</td>
                    <td className="font-mono text-sm">
                      {edge.src_event_id === null ? "—" : edge.src_event_id}
                    </td>
                    <td className="font-mono text-sm">{edge.dst_anomaly_id}</td>
                    <td className="font-mono text-sm">{edge.relation_type}</td>
                    <td className="font-mono text-sm">
                      {displayValue(edge.session_id)}
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
              label="Edge pages"
            />
          ) : null}
        </>
      )}
    </section>
  );
}
