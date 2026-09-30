import Link from "next/link";
import { LinkDocsMore } from "@/components/docs/LinkDocsMore";
import { pipelineHref } from "@/lib/hrefs";
import {
  docsSingleWriterHref,
  docsTroubleshootingHref,
} from "@/lib/docs-links";

type AlertWarehouseBusyProps = {
  retryHref?: string;
};

export function AlertWarehouseBusy({
  retryHref = ".",
}: AlertWarehouseBusyProps) {
  return (
    <div role="alert" className="alert alert-warning">
      <div className="flex w-full flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <span>
          Warehouse is busy (pipeline has the DuckDB write lock). Retry in a few
          seconds.{" "}
          <LinkDocsMore href={docsSingleWriterHref()}>
            Single-writer rules
          </LinkDocsMore>
          {" · "}
          <LinkDocsMore href={docsTroubleshootingHref()}>
            Troubleshooting
          </LinkDocsMore>
        </span>
        <a href={retryHref} className="btn btn-primary btn-sm shrink-0">
          Retry
        </a>
      </div>
    </div>
  );
}

/** Empty / wiped warehouse — not the same as DuckDB writer lock busy. */
export function AlertWarehouseMissing() {
  return (
    <div role="alert" className="alert">
      <div className="flex w-full flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <span>
          No warehouse yet (lab was cleared or correlate has not run). Stage logs
          and start a run from Pipeline.{" "}
          <LinkDocsMore href={docsTroubleshootingHref()}>
            Troubleshooting
          </LinkDocsMore>
        </span>
        <Link className="btn btn-primary btn-sm shrink-0" href={pipelineHref()}>
          Pipeline
        </Link>
      </div>
    </div>
  );
}

type AlertWarehouseStateProps = {
  reason: "warehouse_busy" | "warehouse_missing";
  retryHref?: string;
};

/** Pick busy vs missing alert from an API fail reason. */
export function AlertWarehouseState({
  reason,
  retryHref = ".",
}: AlertWarehouseStateProps) {
  if (reason === "warehouse_missing") {
    return <AlertWarehouseMissing />;
  }
  return <AlertWarehouseBusy retryHref={retryHref} />;
}
