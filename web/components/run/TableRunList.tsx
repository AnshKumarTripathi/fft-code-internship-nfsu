import { NavPagination } from "@/components/layout/NavPagination";
import { formatUtc, runStatusBadgeClass, shortId, RUN_PAGE_SIZE } from "@/lib/format";
import { runsHref } from "@/lib/hrefs";
import type { PipelineRunItem } from "@/lib/types";

type TableRunListProps = {
  items: PipelineRunItem[];
  total: number;
  offset: number;
};

export function TableRunList({ items, total, offset }: TableRunListProps) {
  if (items.length === 0 && total === 0) {
    return (
      <div role="alert" className="alert">
        <span>No pipeline_runs rows in the warehouse yet.</span>
      </div>
    );
  }

  const page = Math.floor(offset / RUN_PAGE_SIZE) + 1;
  const showingFrom = items.length ? offset + 1 : 0;
  const showingTo = offset + items.length;
  const totalPages = total ? Math.max(1, Math.ceil(total / RUN_PAGE_SIZE)) : 1;

  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm text-base-content/70">
        Showing {showingFrom}–{showingTo} of {total}
      </p>
      <div className="fft-paper-panel overflow-x-auto">
        <table className="table table-sm">
          <thead>
            <tr className="text-xs uppercase tracking-wide text-base-content/60">
              <th>Stage</th>
              <th>Status</th>
              <th>Started (UTC)</th>
              <th>Finished (UTC)</th>
              <th>Run id</th>
            </tr>
          </thead>
          <tbody>
            {items.map((run) => (
              <tr key={run.run_id}>
                <td className="font-medium">{run.stage}</td>
                <td>
                  <span className={runStatusBadgeClass(run.status)}>
                    {run.status}
                  </span>
                </td>
                <td className="fft-mono-meta">{formatUtc(run.started_at)}</td>
                <td className="fft-mono-meta">{formatUtc(run.finished_at)}</td>
                <td className="fft-mono-meta" title={run.run_id}>
                  {shortId(run.run_id)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <NavPagination
        page={page}
        totalPages={totalPages}
        hrefForPage={(next) => runsHref(next)}
        label="Run pages"
      />
    </div>
  );
}
