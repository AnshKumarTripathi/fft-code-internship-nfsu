import { AlertApiDown } from "@/components/feedback/AlertApiDown";
import { AlertWarehouseBusy } from "@/components/feedback/AlertWarehouseBusy";
import { PanelReportAddToChat } from "@/components/copilot/PanelReportAddToChat";
import { PageHeader } from "@/components/layout/PageHeader";
import { fetchReportText, reportFileUrl } from "@/lib/api";
import { shortId } from "@/lib/format";
import { incidentHref, reportHref, reportsHref } from "@/lib/hrefs";
import {
  htmlSiblingFilename,
  incidentIdFromReportFilename,
  isAiInsightFilename,
  isSafeReportFilename,
} from "@/lib/reports";
import Link from "next/link";
import { notFound } from "next/navigation";

export const dynamic = "force-dynamic";

type ReportViewerPageProps = {
  params: Promise<{ filename: string }>;
};

export default async function ReportViewerPage({
  params,
}: ReportViewerPageProps) {
  const { filename: raw } = await params;
  const filename = decodeURIComponent(raw);
  if (!isSafeReportFilename(filename)) {
    notFound();
  }

  const retryHref = reportHref(filename);
  const isHtml = filename.endsWith(".html");
  const isInsight = isAiInsightFilename(filename);
  const htmlSibling = htmlSiblingFilename(filename);
  const incidentId = incidentIdFromReportFilename(filename);
  const pageTitle = isInsight ? "AI Insight" : "Report";

  if (isHtml) {
    return (
      <div className="fft-page">
        <PageHeader
          eyebrow={
            <>
              <Link href={reportsHref()} className="link">
                Reports
              </Link>
              {" / "}
              <span className="fft-mono-meta normal-case" title={filename}>
                {filename}
              </span>
            </>
          }
          title={pageTitle}
          actions={
            <>
              <Link
                className="fft-mono-meta link"
                href={incidentHref(incidentId)}
                title={incidentId}
              >
                incident {shortId(incidentId)}
              </Link>
              <a
                className="btn btn-sm btn-ghost"
                href={reportFileUrl(filename)}
                target="_blank"
                rel="noreferrer"
              >
                Open raw
              </a>
            </>
          }
        />
        <iframe
          title={filename}
          src={reportFileUrl(filename)}
          className="fft-paper-panel h-[80vh] w-full"
        />
      </div>
    );
  }

  const result = await fetchReportText(filename);
  if (!result.ok) {
    if (result.status === 404) {
      notFound();
    }
    if (result.reason === "warehouse_busy" || result.reason === "warehouse_missing") {
      return <AlertWarehouseBusy retryHref={retryHref} />;
    }
    return <AlertApiDown />;
  }

  return (
    <div className="fft-page">
      <PageHeader
        eyebrow={
          <>
            <Link href={reportsHref()} className="link">
              Reports
            </Link>
            {" / "}
            <span className="fft-mono-meta normal-case" title={filename}>
              {filename}
            </span>
          </>
        }
        title={pageTitle}
        actions={
          <>
            <Link
              className="fft-mono-meta link"
              href={incidentHref(incidentId)}
              title={incidentId}
            >
              incident {shortId(incidentId)}
            </Link>
            {htmlSibling ? (
              <Link
                className="btn btn-sm btn-primary"
                href={reportHref(htmlSibling)}
              >
                View HTML
              </Link>
            ) : null}
            <PanelReportAddToChat
              filename={filename}
              incidentId={incidentId}
              markdown={result.data}
            />
            <a
              className="btn btn-sm btn-ghost"
              href={reportFileUrl(filename)}
              target="_blank"
              rel="noreferrer"
            >
              Open raw
            </a>
          </>
        }
      />
      {isInsight ? (
        <p className="mb-3 text-sm text-base-content/70" role="note">
          Assistive only — verify against Why flagged and the deterministic
          report. This summary does not change severity or detector scores.
        </p>
      ) : null}
      <article className="fft-paper-panel p-4">
        <pre className="whitespace-pre-wrap font-mono text-sm">{result.data}</pre>
      </article>
    </div>
  );
}
