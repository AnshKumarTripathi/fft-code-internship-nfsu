import Link from "next/link";
import { LinkDocsMore } from "@/components/docs/LinkDocsMore";
import {
  analysisStatusBadgeClass,
  formatUtc,
  shortDigest,
} from "@/lib/format";
import { docsContainersHref, docsSnapshotsHref } from "@/lib/docs-links";
import { pipelineHref } from "@/lib/hrefs";
import type { AnalysisItem } from "@/lib/types";

type BadgeAnalysisChromeProps = {
  analysis: AnalysisItem;
  capturedAt?: string | null;
};

export function BadgeAnalysisChrome({
  analysis,
  capturedAt = null,
}: BadgeAnalysisChromeProps) {
  const correlated =
    capturedAt ||
    (analysis.status === "ready" ? analysis.updated_at : null);

  return (
    <div
      role="status"
      className="fft-sticky-chrome flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3 text-sm"
    >
      <span>
        Analysis: <span className="font-medium">{analysis.label}</span>
      </span>
      <span
        className={`${analysisStatusBadgeClass(analysis.status)} capitalize`}
      >
        {analysis.status}
      </span>
      <span
        className="fft-mono-meta"
        title={analysis.corpus_digest ?? undefined}
      >
        corpus {shortDigest(analysis.corpus_digest)}
      </span>
      {analysis.file_count != null ? (
        <span className="text-base-content/70">{analysis.file_count} files</span>
      ) : null}
      {correlated ? (
        <span className="text-base-content/70">
          Correlated (UTC):{" "}
          <span className="fft-mono-meta">{formatUtc(correlated)}</span>
        </span>
      ) : null}
      <Link className="btn btn-ghost btn-xs" href={pipelineHref()}>
        Pipeline
      </Link>
      <LinkDocsMore
        href={docsSnapshotsHref()}
        className="link link-primary text-xs"
      >
        About snapshots
      </LinkDocsMore>
      <LinkDocsMore
        href={docsContainersHref()}
        className="link link-primary text-xs"
      >
        Containers
      </LinkDocsMore>
    </div>
  );
}
