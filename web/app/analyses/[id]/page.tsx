import { BadgeAnalysisChrome } from "@/components/analysis/BadgeAnalysisChrome";
import { AlertApiDown } from "@/components/feedback/AlertApiDown";
import { AlertWarehouseBusy } from "@/components/feedback/AlertWarehouseBusy";
import { TableIncidentList } from "@/components/incident/TableIncidentList";
import { StatIncidentKpis } from "@/components/kpi/StatIncidentKpis";
import { PageHeader } from "@/components/layout/PageHeader";
import {
  fetchAnalysis,
  fetchAnalysisIncidents,
  fetchAnalysisKpis,
} from "@/lib/api";
import { INCIDENT_PAGE_SIZE, parsePage, shortId } from "@/lib/format";
import { analysisTriageHref, pipelineHref } from "@/lib/hrefs";
import Link from "next/link";

export const dynamic = "force-dynamic";

type AnalysisTriageSearchParams = {
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

type AnalysisTriagePageProps = {
  params: Promise<{ id: string }>;
  searchParams: Promise<AnalysisTriageSearchParams>;
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

export default async function AnalysisTriagePage({
  params,
  searchParams,
}: AnalysisTriagePageProps) {
  const { id: analysisId } = await params;
  const query = await searchParams;
  const severity = query.severity?.trim() ?? "";
  const entityId = query.entity_id?.trim() ?? "";
  const q = query.q?.trim() ?? "";
  const startAfter = query.start_after?.trim() ?? "";
  const endBefore = query.end_before?.trim() ?? "";
  const detector = query.detector?.trim() ?? "";
  const minDetectors = parseMinDetectors(query.min_detectors);
  // Snapshots do not store dismissals — default to all rows.
  const disposition = query.disposition?.trim() || "any";
  const sort = query.sort?.trim() || "severity";
  const order = query.order?.trim() || "desc";
  const page = parsePage(query.page);
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
  const listHref = (hrefParams: Parameters<typeof analysisTriageHref>[1]) =>
    analysisTriageHref(analysisId, hrefParams);
  const retryHref = analysisTriageHref(analysisId, {
    ...listFilters,
    page,
  });
  const formAction = `/analyses/${encodeURIComponent(analysisId)}`;

  const analysisResult = await fetchAnalysis(analysisId);
  if (!analysisResult.ok) {
    if (analysisResult.reason === "warehouse_busy" || analysisResult.reason === "warehouse_missing") {
      return <AlertWarehouseBusy retryHref={retryHref} />;
    }
    if (analysisResult.status === 404) {
      return (
        <div className="fft-page">
          <PageHeader
            title="Analysis not found"
            blurb={
              <>
                No container with id{" "}
                <span className="fft-mono-meta" title={analysisId}>
                  {shortId(analysisId)}
                </span>
                .
              </>
            }
          />
          <Link className="btn btn-primary btn-sm w-fit" href={pipelineHref()}>
            Back to Pipeline
          </Link>
        </div>
      );
    }
    return <AlertApiDown />;
  }

  const [kpisResult, incidentsResult] = await Promise.all([
    fetchAnalysisKpis(analysisId),
    fetchAnalysisIncidents(analysisId, {
      ...listFilters,
      limit: INCIDENT_PAGE_SIZE,
      offset,
    }),
  ]);

  if (!kpisResult.ok) {
    if (kpisResult.reason === "warehouse_busy" || kpisResult.reason === "warehouse_missing") {
      return <AlertWarehouseBusy retryHref={retryHref} />;
    }
    if (kpisResult.status === 404) {
      return (
        <div className="fft-page">
          <BadgeAnalysisChrome analysis={analysisResult.data} />
          <PageHeader title={analysisResult.data.label} />
          <div role="alert" className="alert alert-warning">
            <span>
              No triage snapshot yet. Snapshots are written after a successful
              correlate. Start or finish a run from Pipeline.
            </span>
          </div>
          <Link className="btn btn-primary btn-sm w-fit" href={pipelineHref()}>
            Open Pipeline
          </Link>
        </div>
      );
    }
    return <AlertApiDown />;
  }
  if (!incidentsResult.ok) {
    if (incidentsResult.reason === "warehouse_busy" || incidentsResult.reason === "warehouse_missing") {
      return <AlertWarehouseBusy retryHref={retryHref} />;
    }
    return <AlertApiDown />;
  }

  return (
    <div className="fft-page">
      <BadgeAnalysisChrome analysis={analysisResult.data} />
      <PageHeader
        eyebrow={
          <>
            <Link className="link" href={pipelineHref()}>
              Pipeline
            </Link>
            {" / "}
            Analysis triage
          </>
        }
        title={analysisResult.data.label}
        blurb={
          <>
            Snapshot incident list for this container. Entity charts and STFT on
            incident detail pages still read the <em>live</em> warehouse — they
            may not match a past run.
          </>
        }
      />
      <StatIncidentKpis
        kpis={kpisResult.data}
        filters={{ ...listFilters, disposition }}
        listHref={listHref}
        caption="KPIs from this analysis snapshot (not live warehouse filters)."
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
        listHref={listHref}
        formAction={formAction}
      />
    </div>
  );
}
