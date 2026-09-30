import Link from "next/link";
import { pipelineHref, runsHref } from "@/lib/hrefs";

export function AlertPipelineNotRun() {
  return (
    <div role="alert" className="alert">
      <div className="flex w-full flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <span>
          Pipeline has not finished correlate, so there are no incident flags
          yet (this is not the same as “no flags”). Start a run from Pipeline,
          or check Runs for the last stage.
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
