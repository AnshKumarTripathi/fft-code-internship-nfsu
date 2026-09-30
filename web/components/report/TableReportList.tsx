import Link from "next/link";
import { NavPagination } from "@/components/layout/NavPagination";
import { reportFileUrl } from "@/lib/api";
import { incidentHref, reportHref, reportsHref } from "@/lib/hrefs";
import { REPORT_PAGE_SIZE, shortId } from "@/lib/format";
import type { ReportFileItem } from "@/lib/types";

type TableReportListProps = {
  items: ReportFileItem[];
  total: number;
  offset: number;
};

export function TableReportList({ items, total, offset }: TableReportListProps) {
  if (items.length === 0 && total === 0) {
    return (
      <div role="alert" className="alert">
        <div className="flex w-full flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <span>
            No report files. From <code>code/</code>, run{" "}
            <code>python -m src.pipeline report</code> after correlate, then
            refresh.
          </span>
          <Link className="btn btn-primary btn-sm" href="/">
            Pipeline
          </Link>
        </div>
      </div>
    );
  }

  const page = Math.floor(offset / REPORT_PAGE_SIZE) + 1;
  const showingFrom = items.length ? offset + 1 : 0;
  const showingTo = offset + items.length;
  const totalPages = total ? Math.max(1, Math.ceil(total / REPORT_PAGE_SIZE)) : 1;

  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm text-base-content/70">
        Showing {showingFrom}–{showingTo} of {total}
      </p>
      <div className="fft-paper-panel overflow-x-auto">
        <table className="table table-sm">
          <thead>
            <tr className="text-xs uppercase tracking-wide text-base-content/60">
              <th>Report</th>
              <th>Incident</th>
              <th>Media type</th>
            </tr>
          </thead>
          <tbody>
            {items.map((report) => (
              <tr key={report.filename}>
                <td>
                  <Link
                    className="link text-sm font-medium"
                    href={reportHref(report.filename)}
                    title={report.filename}
                  >
                    {report.filename.endsWith("_ai_insight.md")
                      ? "AI Insight"
                      : report.filename}
                  </Link>
                  {report.filename.endsWith("_ai_insight.md") ? (
                    <span className="ml-2 text-xs text-base-content/50">
                      {report.filename}
                    </span>
                  ) : null}
                </td>
                <td>
                  <Link
                    className="fft-mono-meta link"
                    href={incidentHref(report.incident_id)}
                    title={report.incident_id}
                  >
                    {shortId(report.incident_id)}
                  </Link>
                </td>
                <td>
                  <span>{report.media_type}</span>
                  {" · "}
                  <a
                    className="link text-sm"
                    href={reportFileUrl(report.filename)}
                    target="_blank"
                    rel="noreferrer"
                  >
                    raw
                  </a>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <NavPagination
        page={page}
        totalPages={totalPages}
        hrefForPage={(next) => reportsHref(next)}
        label="Report pages"
      />
    </div>
  );
}
