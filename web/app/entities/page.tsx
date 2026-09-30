import { AlertApiDown } from "@/components/feedback/AlertApiDown";
import { AlertWarehouseState } from "@/components/feedback/AlertWarehouseBusy";
import { TableEntityList } from "@/components/entity/TableEntityList";
import { PageHeader } from "@/components/layout/PageHeader";
import { fetchEntities } from "@/lib/api";
import { ENTITY_PAGE_SIZE } from "@/lib/format";
import { entityListHref } from "@/lib/hrefs";

export const dynamic = "force-dynamic";

type EntitiesSearchParams = {
  q?: string;
  page?: string;
};

type EntitiesPageProps = {
  searchParams: Promise<EntitiesSearchParams>;
};

function parsePage(raw: string | undefined): number {
  const parsed = Number.parseInt(raw ?? "1", 10);
  if (!Number.isFinite(parsed) || parsed < 1) {
    return 1;
  }
  return parsed;
}

export default async function EntitiesPage({ searchParams }: EntitiesPageProps) {
  const params = await searchParams;
  const q = params.q?.trim() ?? "";
  const page = parsePage(params.page);
  const offset = (page - 1) * ENTITY_PAGE_SIZE;
  const retryHref = entityListHref(q || undefined, page);

  const result = await fetchEntities({
    q: q || undefined,
    limit: ENTITY_PAGE_SIZE,
    offset,
  });

  if (!result.ok) {
    if (result.reason === "warehouse_busy" || result.reason === "warehouse_missing") {
      return <AlertWarehouseState reason={result.reason} retryHref={retryHref} />;
    }
    return <AlertApiDown />;
  }

  return (
    <div className="fft-page">
      <PageHeader
        eyebrow="Registry"
        title="Entities"
        blurb="Search the entity registry. Open a row for activity, spectrum, and incidents."
      />
      <TableEntityList
        items={result.data.items}
        q={q}
        total={result.data.total}
        offset={result.data.offset}
      />
    </div>
  );
}
