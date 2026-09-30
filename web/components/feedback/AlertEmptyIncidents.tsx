import Link from "next/link";
import { LinkDocsMore } from "@/components/docs/LinkDocsMore";
import { docsTroubleshootingHref } from "@/lib/docs-links";
import { pipelineHref, runsHref } from "@/lib/hrefs";

export function AlertEmptyIncidents() {
  return (
    <div role="alert" className="alert">
      <div className="flex w-full flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <span>
          Correlate finished with no incidents — no detector crossed the cutoff.
          That is not the same as “pipeline not run”. Start another analysis if
          you have new logs, or check Runs for the last successful correlate.{" "}
          <LinkDocsMore href={docsTroubleshootingHref()}>
            Troubleshooting
          </LinkDocsMore>
        </span>
        <div className="flex flex-wrap gap-2">
          <Link className="btn btn-primary btn-sm" href={pipelineHref()}>
            Pipeline
          </Link>
          <Link className="btn btn-ghost btn-sm" href={runsHref()}>
            Runs
          </Link>
        </div>
      </div>
    </div>
  );
}
