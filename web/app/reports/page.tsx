import { AlertApiDown } from "@/components/feedback/AlertApiDown";
import { AlertWarehouseBusy } from "@/components/feedback/AlertWarehouseBusy";
import { PageHeader } from "@/components/layout/PageHeader";
import { TableReportList } from "@/components/report/TableReportList";
import { fetchReports } from "@/lib/api";
import { REPORT_PAGE_SIZE } from "@/lib/format";
import { reportsHref } from "@/lib/hrefs";

export const dynamic = "force-dynamic";

type ReportsPageProps = {
  searchParams: Promise<{ page?: string }>;
};

function parsePage(raw: string | undefined): number {
  const parsed = Number.parseInt(raw ?? "1", 10);
  if (!Number.isFinite(parsed) || parsed < 1) {
    return 1;
  }
  return parsed;
}

export default async function ReportsPage({ searchParams }: ReportsPageProps) {
  const params = await searchParams;
  const page = parsePage(params.page);
  const offset = (page - 1) * REPORT_PAGE_SIZE;
  const result = await fetchReports({ limit: REPORT_PAGE_SIZE, offset });

  if (!result.ok) {
    if (result.reason === "warehouse_busy" || result.reason === "warehouse_missing") {
      return <AlertWarehouseBusy retryHref={reportsHref(page)} />;
    }
    return <AlertApiDown />;
  }

  return (
    <div className="fft-page">
      <PageHeader
        eyebrow="Artifacts"
        title="Reports"
        blurb={
          <>
            Deterministic Markdown and HTML artifacts from{" "}
            <code>python -m src.pipeline report</code>. Open a row to view in
            this app; raw files remain on the JSON API.
          </>
        }
      />
      <TableReportList
        items={result.data.items}
        total={result.data.total}
        offset={result.data.offset}
      />
    </div>
  );
}
