import { AlertApiDown } from "@/components/feedback/AlertApiDown";
import { AlertWarehouseState } from "@/components/feedback/AlertWarehouseBusy";
import { TableIncidentList } from "@/components/incident/TableIncidentList";
import { StatIncidentKpis } from "@/components/kpi/StatIncidentKpis";
import { PageHeader } from "@/components/layout/PageHeader";
import { BannerPipelineJob } from "@/components/run/BannerPipelineJob";
import { fetchIncidents, fetchKpis } from "@/lib/api";
import { INCIDENT_PAGE_SIZE, parsePage } from "@/lib/format";
import { incidentListHref } from "@/lib/hrefs";

export const dynamic = "force-dynamic";

type TriageSearchParams = {
  severity?: string;
  entity_id?: string;
  q?: string;
  start_after?: string;
  end_before?: string;
  detector?: string;
  min_detectors?: string;
  disposition?: string;
  sort?: string;
  order?: string;
  page?: string;
};

type TriagePageProps = {
  searchParams: Promise<TriageSearchParams>;
};

function parseMinDetectors(raw: string | undefined): number | undefined {
  if (!raw?.trim()) {
    return undefined;
  }
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed < 1) {
    return undefined;
  }
  return parsed;
}

export default async function TriagePage({ searchParams }: TriagePageProps) {
  const params = await searchParams;
  const severity = params.severity?.trim() ?? "";
  const entityId = params.entity_id?.trim() ?? "";
  const q = params.q?.trim() ?? "";
  const startAfter = params.start_after?.trim() ?? "";
  const endBefore = params.end_before?.trim() ?? "";
  const detector = params.detector?.trim() ?? "";
  const minDetectors = parseMinDetectors(params.min_detectors);
  // Phase 48: default triage queue is open (needs review).
  const disposition = params.disposition?.trim() || "open";
  const sort = params.sort?.trim() || "severity";
  const order = params.order?.trim() || "desc";
  const page = parsePage(params.page);
  const offset = (page - 1) * INCIDENT_PAGE_SIZE;
  const listFilters = {
    severity: severity || undefined,
    entity_id: entityId || undefined,
    q: q || undefined,
    start_after: startAfter || undefined,
    end_before: endBefore || undefined,
    detector: detector || undefined,
    min_detectors: minDetectors,
    disposition: disposition !== "any" ? disposition : undefined,
    sort: sort !== "severity" ? sort : undefined,
    order: order === "asc" ? order : undefined,
  };
  const retryHref = incidentListHref({ ...listFilters, page });

  const [kpisResult, incidentsResult] = await Promise.all([
    fetchKpis(),
    fetchIncidents({
      ...listFilters,
      limit: INCIDENT_PAGE_SIZE,
      offset,
    }),
  ]);

  if (!kpisResult.ok) {
    if (kpisResult.reason === "warehouse_busy" || kpisResult.reason === "warehouse_missing") {
      return <AlertWarehouseState reason={kpisResult.reason} retryHref={retryHref} />;
    }
    return <AlertApiDown />;
  }
  if (!incidentsResult.ok) {
    if (incidentsResult.reason === "warehouse_busy" || incidentsResult.reason === "warehouse_missing") {
      return (
        <AlertWarehouseState
          reason={incidentsResult.reason}
          retryHref={retryHref}
        />
      );
    }
    return <AlertApiDown />;
  }

  return (
    <div className="fft-page">
      <PageHeader
        eyebrow="Live warehouse"
        title="Triage"
        blurb={
          <>
            Correlated anomalies from the <em>live</em> warehouse — not a named
            analysis container. Named analyses on Pipeline open snapshot triage
            at <code>/analyses/&lt;id&gt;</code>. Entity charts still follow the
            live warehouse. Start a new corpus from Pipeline if this list is
            empty or stale.
          </>
        }
      />
      <BannerPipelineJob showIdleLink />
      <StatIncidentKpis
        kpis={kpisResult.data}
        filters={{ ...listFilters, disposition }}
      />
      <TableIncidentList
        items={incidentsResult.data.items}
        total={incidentsResult.data.total}
        offset={incidentsResult.data.offset}
        severity={severity}
        entityId={entityId}
        q={q}
        startAfter={startAfter}
        endBefore={endBefore}
        detector={detector}
        minDetectors={minDetectors}
        disposition={disposition}
        sort={sort}
        order={order}
        warehouseEmpty={kpisResult.data.total === 0}
        pipelineRan={Boolean(kpisResult.data.last_correlate_at)}
      />
    </div>
  );
}
