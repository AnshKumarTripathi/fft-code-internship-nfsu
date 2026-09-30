import Link from "next/link";
import { reportFileUrl } from "@/lib/api";
import { htmlReportHref, reportHref } from "@/lib/hrefs";
import { isAiInsightFilename } from "@/lib/reports";
import type { ReportFileItem } from "@/lib/types";

type CardIncidentReportsProps = {
  reports: ReportFileItem[];
  incidentId: string;
};

export function CardIncidentReports({
  reports,
  incidentId,
}: CardIncidentReportsProps) {
  const html = reports.find(
    (item) => item.filename.endsWith(".html") && !isAiInsightFilename(item.filename),
  );
  const markdown = reports.find(
    (item) =>
      item.filename.endsWith(".md") && !isAiInsightFilename(item.filename),
  );
  const insight = reports.find((item) => isAiInsightFilename(item.filename));
  const viewHref = html
    ? reportHref(html.filename)
    : markdown
      ? reportHref(markdown.filename)
      : htmlReportHref(incidentId);

  return (
    <section className="flex flex-col gap-3">
      <h2 className="text-lg font-semibold">Report</h2>
      {reports.length === 0 ? (
        <div role="alert" className="alert">
          <span>
            No report file yet. From <code>code/</code>, run{" "}
            <code>python -m src.pipeline report</code> after correlate, then
            refresh.
          </span>
        </div>
      ) : (
        <p className="flex flex-wrap gap-2">
          {(html || markdown) && (
            <Link className="btn btn-sm btn-primary" href={viewHref}>
              View report
            </Link>
          )}
          {insight ? (
            <Link className="btn btn-sm btn-secondary" href={reportHref(insight.filename)}>
              AI Insight
            </Link>
          ) : null}
          {html ? (
            <a
              className="btn btn-sm"
              href={reportFileUrl(html.filename)}
              target="_blank"
              rel="noreferrer"
            >
              Raw HTML
            </a>
          ) : null}
          {markdown ? (
            <a
              className="btn btn-sm"
              href={reportFileUrl(markdown.filename)}
              target="_blank"
              rel="noreferrer"
            >
              Raw Markdown
            </a>
          ) : null}
        </p>
      )}
    </section>
  );
}
