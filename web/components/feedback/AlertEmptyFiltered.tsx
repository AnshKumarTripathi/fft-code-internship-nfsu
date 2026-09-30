import Link from "next/link";
import { pipelineHref } from "@/lib/hrefs";

export function AlertEmptyFiltered() {
  return (
    <div role="alert" className="alert">
      <div className="flex w-full flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <span>
          No incidents match the current filters. Adjust filters, or start a run
          from Pipeline (home). Power users can also run{" "}
          <code>python -m src.pipeline run-all</code> from <code>code/</code>.
        </span>
        <Link className="btn btn-primary btn-sm shrink-0" href={pipelineHref()}>
          Pipeline
        </Link>
      </div>
    </div>
  );
}
