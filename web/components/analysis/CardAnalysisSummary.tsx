import Link from "next/link";
import {
  analysisStatusBadgeClass,
  formatUtc,
  shortDigest,
} from "@/lib/format";
import { analysisTriageHref, pipelineHref } from "@/lib/hrefs";
import type { AnalysisItem } from "@/lib/types";

type CardAnalysisSummaryProps = {
  analysis: AnalysisItem;
  isActive?: boolean;
  onContinue?: (analysis: AnalysisItem) => void;
};

export function CardAnalysisSummary({
  analysis,
  isActive = false,
  onContinue,
}: CardAnalysisSummaryProps) {
  const canOpenTriage =
    analysis.status === "ready" || analysis.status === "running";
  const canContinue =
    analysis.status === "draft" ||
    analysis.status === "failed" ||
    analysis.status === "ready";

  return (
    <article
      className={`fft-paper-panel flex flex-col gap-3 p-4 ${
        isActive ? "border-primary bg-primary/5" : ""
      }`}
    >
      <div className="flex flex-wrap items-start justify-between gap-2">
        <h3 className="text-base font-semibold leading-snug">{analysis.label}</h3>
        <span
          className={`${analysisStatusBadgeClass(analysis.status)} capitalize`}
        >
          {analysis.status}
        </span>
      </div>
      <dl className="grid gap-2 text-sm sm:grid-cols-2">
        <div>
          <dt className="text-xs uppercase tracking-wide text-base-content/60">
            Corpus
          </dt>
          <dd
            className="fft-mono-meta"
            title={analysis.corpus_digest ?? undefined}
          >
            {shortDigest(analysis.corpus_digest)}
          </dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wide text-base-content/60">
            Files
          </dt>
          <dd>{analysis.file_count ?? "—"}</dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wide text-base-content/60">
            Created (UTC)
          </dt>
          <dd className="fft-mono-meta">{formatUtc(analysis.created_at)}</dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wide text-base-content/60">
            Updated (UTC)
          </dt>
          <dd className="fft-mono-meta">{formatUtc(analysis.updated_at)}</dd>
        </div>
      </dl>
      <div className="flex flex-wrap gap-2">
        {canOpenTriage ? (
          <Link
            className="btn btn-sm btn-primary"
            href={analysisTriageHref(analysis.analysis_id, {
              disposition: analysis.status === "ready" ? "any" : "open",
            })}
          >
            Open triage
          </Link>
        ) : null}
        {canContinue && onContinue ? (
          <button
            type="button"
            className="btn btn-sm btn-ghost"
            onClick={() => onContinue(analysis)}
          >
            Continue
          </button>
        ) : canContinue ? (
          <Link className="btn btn-sm btn-ghost" href={pipelineHref()}>
            Continue
          </Link>
        ) : null}
      </div>
    </article>
  );
}
