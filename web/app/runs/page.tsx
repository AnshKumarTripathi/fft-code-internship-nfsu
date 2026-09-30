import Link from "next/link";
import { AlertApiDown } from "@/components/feedback/AlertApiDown";
import { AlertWarehouseState } from "@/components/feedback/AlertWarehouseBusy";
import { PageHeader } from "@/components/layout/PageHeader";
import { BannerPipelineJob } from "@/components/run/BannerPipelineJob";
import { TableRunList } from "@/components/run/TableRunList";
import { fetchRuns } from "@/lib/api";
import { RUN_PAGE_SIZE } from "@/lib/format";
import { pipelineHref, runsHref } from "@/lib/hrefs";

export const dynamic = "force-dynamic";

type RunsPageProps = {
  searchParams: Promise<{ page?: string }>;
};

function parsePage(raw: string | undefined): number {
  const parsed = Number.parseInt(raw ?? "1", 10);
  if (!Number.isFinite(parsed) || parsed < 1) {
    return 1;
  }
  return parsed;
}

export default async function RunsPage({ searchParams }: RunsPageProps) {
  const params = await searchParams;
  const page = parsePage(params.page);
  const offset = (page - 1) * RUN_PAGE_SIZE;
  const result = await fetchRuns({ limit: RUN_PAGE_SIZE, offset });

  if (!result.ok) {
    if (result.reason === "warehouse_busy" || result.reason === "warehouse_missing") {
      return (
        <AlertWarehouseState
          reason={result.reason}
          retryHref={runsHref(page)}
        />
      );
    }
    return <AlertApiDown />;
  }

  return (
    <div className="fft-page">
      <PageHeader
        eyebrow="History"
        title="Runs"
        blurb={
          <>
            Historical <code>pipeline_runs</code> rows from the warehouse. Start
            or watch a live job from{" "}
            <Link className="link" href={pipelineHref()}>
              Pipeline
            </Link>
            ; this table is read-only and there is no cancel action. CLI{" "}
            <code>run-all</code> remains available for power users.
          </>
        }
      />
      <BannerPipelineJob showIdleLink />
      <TableRunList
        items={result.data.items}
        total={result.data.total}
        offset={result.data.offset}
      />
    </div>
  );
}
