import { apiBaseUrl } from "@/lib/env";
import type {
  AnalystActionCreate,
  AnalystActionItem,
  AnalysisCreate,
  AnalysisItem,
  AnalysisUpdate,
  BucketSeriesResponse,
  EntityListParams,
  EntityMeta,
  IncidentDetail,
  IncidentEdgeItem,
  IncidentItem,
  IncidentKpis,
  IncidentListParams,
  IncidentTimelineEvent,
  ListEnvelope,
  PipelineJobCreate,
  PipelineJobStatus,
  PipelineLabResetRequest,
  PipelineLabResetResponse,
  PipelineCorpusListResponse,
  PipelineRunItem,
  PipelineShardingSettings,
  PipelineUploadListResponse,
  ReportFileItem,
  SpectrumResponse,
  StftMatrixResponse,
  TimelineEvent,
  UiHonestyPolicy,
  WindowQuery,
  CopilotAttachment,
  CopilotChatMessage,
  CopilotChatResponse,
  CopilotStatus,
} from "@/lib/types";

export type ApiOk<T> = { ok: true; data: T };

export type ApiFail = {
  ok: false;
  status: number | null;
  reason: "api_down" | "warehouse_busy" | "warehouse_missing" | "http_error";
  message: string;
};

export type ApiResult<T> = ApiOk<T> | ApiFail;

export function isWarehouseUnavailable(
  reason: ApiFail["reason"] | string | undefined,
): reason is "warehouse_busy" | "warehouse_missing" {
  return reason === "warehouse_busy" || reason === "warehouse_missing";
}

const API_DOWN_MESSAGE =
  "The JSON API is not running. From `code/`, start `uvicorn src.api.main:app --host 127.0.0.1 --port 8000`.";

const WAREHOUSE_BUSY_MESSAGE =
  "Warehouse is busy (pipeline has the DuckDB write lock). Retry in a few seconds.";

const WAREHOUSE_MISSING_MESSAGE =
  "No warehouse yet. Stage logs and start a run from Pipeline.";

function isWarehouseMissingMessage(message: string): boolean {
  const lower = message.toLowerCase();
  return (
    lower.includes("warehouse not found") ||
    lower.includes("no warehouse") ||
    (lower.includes("warehouse") && lower.includes("missing"))
  );
}

function withQuery(
  path: string,
  params?: Record<string, string | number | boolean | null | undefined>,
): string {
  const search = new URLSearchParams();
  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value === undefined || value === null || value === "") {
        continue;
      }
      search.set(key, String(value));
    }
  }
  const qs = search.toString();
  return qs ? `${path}?${qs}` : path;
}

async function fetchJson<T>(path: string): Promise<ApiResult<T>> {
  const url = `${apiBaseUrl()}${path}`;
  try {
    const response = await fetch(url, { cache: "no-store" });
    if (response.status === 503) {
      return {
        ok: false,
        status: 503,
        reason: "warehouse_busy",
        message: WAREHOUSE_BUSY_MESSAGE,
      };
    }
    if (response.status === 404) {
      const message = await readErrorMessage(
        response,
        WAREHOUSE_MISSING_MESSAGE,
      );
      if (isWarehouseMissingMessage(message)) {
        return {
          ok: false,
          status: 404,
          reason: "warehouse_missing",
          message: WAREHOUSE_MISSING_MESSAGE,
        };
      }
      return failFromResponse(404, message);
    }
    if (!response.ok) {
      return {
        ok: false,
        status: response.status,
        reason: "http_error",
        message: `API returned ${response.status}`,
      };
    }
    const data = (await response.json()) as T;
    return { ok: true, data };
  } catch {
    return {
      ok: false,
      status: null,
      reason: "api_down",
      message: API_DOWN_MESSAGE,
    };
  }
}

function failFromResponse(status: number, message: string): ApiFail {
  if (status === 503) {
    return {
      ok: false,
      status,
      reason: "warehouse_busy",
      message: WAREHOUSE_BUSY_MESSAGE,
    };
  }
  if (status === 404 && isWarehouseMissingMessage(message)) {
    return {
      ok: false,
      status,
      reason: "warehouse_missing",
      message: WAREHOUSE_MISSING_MESSAGE,
    };
  }
  return {
    ok: false,
    status,
    reason: "http_error",
    message,
  };
}

function detailMessage(detail: unknown, fallback: string): string {
  if (typeof detail === "string" && detail.trim()) {
    return detail;
  }
  if (detail && typeof detail === "object") {
    const record = detail as { message?: unknown };
    if (typeof record.message === "string" && record.message.trim()) {
      return record.message;
    }
    return JSON.stringify(detail);
  }
  return fallback;
}

async function readErrorMessage(
  response: Response,
  fallback: string,
): Promise<string> {
  try {
    const errorBody = (await response.json()) as { detail?: unknown };
    return detailMessage(errorBody.detail, fallback);
  } catch {
    return fallback;
  }
}

async function postJson<T>(path: string, body: unknown): Promise<ApiResult<T>> {
  const url = `${apiBaseUrl()}${path}`;
  try {
    const response = await fetch(url, {
      method: "POST",
      cache: "no-store",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      const message = await readErrorMessage(
        response,
        `API returned ${response.status}`,
      );
      return failFromResponse(response.status, message);
    }
    const data = (await response.json()) as T;
    return { ok: true, data };
  } catch {
    return {
      ok: false,
      status: null,
      reason: "api_down",
      message: API_DOWN_MESSAGE,
    };
  }
}

async function patchJson<T>(path: string, body: unknown): Promise<ApiResult<T>> {
  const url = `${apiBaseUrl()}${path}`;
  try {
    const response = await fetch(url, {
      method: "PATCH",
      cache: "no-store",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      const message = await readErrorMessage(
        response,
        `API returned ${response.status}`,
      );
      return failFromResponse(response.status, message);
    }
    const data = (await response.json()) as T;
    return { ok: true, data };
  } catch {
    return {
      ok: false,
      status: null,
      reason: "api_down",
      message: API_DOWN_MESSAGE,
    };
  }
}

async function postMultipart<T>(
  path: string,
  formData: FormData,
): Promise<ApiResult<T>> {
  const url = `${apiBaseUrl()}${path}`;
  try {
    const response = await fetch(url, {
      method: "POST",
      cache: "no-store",
      headers: { Accept: "application/json" },
      body: formData,
    });
    if (!response.ok) {
      const message = await readErrorMessage(
        response,
        `API returned ${response.status}`,
      );
      return failFromResponse(response.status, message);
    }
    const data = (await response.json()) as T;
    return { ok: true, data };
  } catch {
    return {
      ok: false,
      status: null,
      reason: "api_down",
      message: API_DOWN_MESSAGE,
    };
  }
}

async function deleteRequest(path: string): Promise<ApiResult<null>> {
  const url = `${apiBaseUrl()}${path}`;
  try {
    const response = await fetch(url, {
      method: "DELETE",
      cache: "no-store",
      headers: { Accept: "application/json" },
    });
    if (!response.ok) {
      const message = await readErrorMessage(
        response,
        `API returned ${response.status}`,
      );
      return failFromResponse(response.status, message);
    }
    return { ok: true, data: null };
  } catch {
    return {
      ok: false,
      status: null,
      reason: "api_down",
      message: API_DOWN_MESSAGE,
    };
  }
}

export function entityPath(entityId: string): string {
  return `/api/v1/entities/${encodeURIComponent(entityId)}`;
}

export function incidentPath(incidentId: string): string {
  return `/api/v1/incidents/${encodeURIComponent(incidentId)}`;
}

export function reportFileUrl(filename: string): string {
  return `${apiBaseUrl()}/api/v1/reports/${encodeURIComponent(filename)}`;
}

export function fetchKpis(): Promise<ApiResult<IncidentKpis>> {
  return fetchJson("/api/v1/kpis");
}

export function fetchIncidents(
  params?: IncidentListParams,
): Promise<ApiResult<ListEnvelope<IncidentItem>>> {
  return fetchJson(withQuery("/api/v1/incidents", params));
}

export function fetchIncident(
  incidentId: string,
): Promise<ApiResult<IncidentDetail>> {
  return fetchJson(incidentPath(incidentId));
}

export function fetchIncidentTimeline(
  incidentId: string,
  params?: { limit?: number; offset?: number },
): Promise<ApiResult<ListEnvelope<IncidentTimelineEvent>>> {
  return fetchJson(withQuery(`${incidentPath(incidentId)}/timeline`, params));
}

export function fetchIncidentEdges(
  incidentId: string,
  params?: { limit?: number; offset?: number },
): Promise<ApiResult<ListEnvelope<IncidentEdgeItem>>> {
  return fetchJson(withQuery(`${incidentPath(incidentId)}/edges`, params));
}

export function fetchEntities(
  params?: EntityListParams,
): Promise<ApiResult<ListEnvelope<EntityMeta>>> {
  return fetchJson(withQuery("/api/v1/entities", params));
}

export function fetchEntity(entityId: string): Promise<ApiResult<EntityMeta>> {
  return fetchJson(entityPath(entityId));
}

export function fetchEntityTimeline(
  entityId: string,
  params?: WindowQuery,
): Promise<ApiResult<ListEnvelope<TimelineEvent>>> {
  return fetchJson(withQuery(`${entityPath(entityId)}/timeline`, params));
}

export function fetchEntitySpectrum(
  entityId: string,
  downsample?: boolean,
): Promise<ApiResult<SpectrumResponse>> {
  return fetchJson(
    withQuery(`${entityPath(entityId)}/spectrum`, { downsample }),
  );
}

export function fetchEntityStft(
  entityId: string,
  params?: WindowQuery,
): Promise<ApiResult<StftMatrixResponse>> {
  return fetchJson(
    withQuery(`${entityPath(entityId)}/stft`, {
      start: params?.start,
      end: params?.end,
    }),
  );
}

export function fetchEntityBuckets(
  entityId: string,
  params?: WindowQuery,
): Promise<ApiResult<BucketSeriesResponse>> {
  return fetchJson(withQuery(`${entityPath(entityId)}/buckets`, params));
}

export function fetchEntityIncidents(
  entityId: string,
  params?: { limit?: number; offset?: number },
): Promise<ApiResult<ListEnvelope<IncidentItem>>> {
  return fetchJson(withQuery(`${entityPath(entityId)}/incidents`, params));
}

export function fetchRuns(params?: {
  limit?: number;
  offset?: number;
}): Promise<ApiResult<ListEnvelope<PipelineRunItem>>> {
  return fetchJson(withQuery("/api/v1/runs", params));
}

export function fetchReports(params?: {
  limit?: number;
  offset?: number;
}): Promise<ApiResult<ListEnvelope<ReportFileItem>>> {
  return fetchJson(withQuery("/api/v1/reports", params));
}

export async function fetchReportText(
  filename: string,
): Promise<ApiResult<string>> {
  const url = reportFileUrl(filename);
  try {
    const response = await fetch(url, { cache: "no-store" });
    if (response.status === 503) {
      return {
        ok: false,
        status: 503,
        reason: "warehouse_busy",
        message: WAREHOUSE_BUSY_MESSAGE,
      };
    }
    if (response.status === 404) {
      return {
        ok: false,
        status: 404,
        reason: "http_error",
        message: "Report file not found",
      };
    }
    if (!response.ok) {
      return {
        ok: false,
        status: response.status,
        reason: "http_error",
        message: `API returned ${response.status}`,
      };
    }
    return { ok: true, data: await response.text() };
  } catch {
    return {
      ok: false,
      status: null,
      reason: "api_down",
      message: API_DOWN_MESSAGE,
    };
  }
}

export function fetchUiPolicy(): Promise<ApiResult<UiHonestyPolicy>> {
  return fetchJson("/api/v1/ui-policy");
}

export function createAnalystAction(
  payload: AnalystActionCreate,
): Promise<ApiResult<AnalystActionItem>> {
  return postJson("/api/v1/actions", payload);
}

export function fetchPipelineUploads(): Promise<
  ApiResult<PipelineUploadListResponse>
> {
  return fetchJson("/api/v1/pipeline/uploads");
}

export function uploadPipelineFiles(
  files: File[],
): Promise<ApiResult<PipelineUploadListResponse>> {
  const formData = new FormData();
  for (const file of files) {
    formData.append("files", file);
  }
  return postMultipart("/api/v1/pipeline/uploads", formData);
}

export function deletePipelineUpload(name: string): Promise<ApiResult<null>> {
  return deleteRequest(`/api/v1/pipeline/uploads/${encodeURIComponent(name)}`);
}

export function seedDemoCorpus(): Promise<
  ApiResult<PipelineUploadListResponse>
> {
  return postJson("/api/v1/pipeline/corpus/demo", {});
}

export function resetLabData(
  payload: PipelineLabResetRequest,
): Promise<ApiResult<PipelineLabResetResponse>> {
  return postJson("/api/v1/pipeline/lab-reset", {
    confirm: payload.confirm,
    clear_uploads: payload.clear_uploads ?? true,
    clear_raw_non_upload: payload.clear_raw_non_upload ?? false,
  });
}

export function createPipelineJob(
  payload: PipelineJobCreate = {},
): Promise<ApiResult<PipelineJobStatus>> {
  return postJson("/api/v1/pipeline/jobs", {
    mode: payload.mode ?? "run_all",
    require_complete: payload.require_complete ?? false,
    stages: payload.stages ?? null,
    analysis_id: payload.analysis_id ?? null,
    label: payload.label ?? null,
    notes: payload.notes ?? null,
    ml_ensemble_enabled: payload.ml_ensemble_enabled ?? null,
    input_path: payload.input_path ?? null,
    use_staged_uploads: payload.use_staged_uploads ?? false,
  });
}

export function cancelPipelineJob(
  jobId: string,
): Promise<ApiResult<PipelineJobStatus>> {
  return postJson(
    `/api/v1/pipeline/jobs/${encodeURIComponent(jobId)}/cancel`,
    {},
  );
}

export function fetchPipelineShardingSettings(): Promise<
  ApiResult<PipelineShardingSettings>
> {
  return fetchJson("/api/v1/pipeline/sharding");
}

export function fetchPipelineCorpusRaw(): Promise<
  ApiResult<PipelineCorpusListResponse>
> {
  return fetchJson("/api/v1/pipeline/corpus/raw");
}

export function fetchPipelineJob(
  jobId: string,
): Promise<ApiResult<PipelineJobStatus>> {
  return fetchJson(`/api/v1/pipeline/jobs/${encodeURIComponent(jobId)}`);
}

export async function fetchLatestPipelineJob(): Promise<
  ApiResult<PipelineJobStatus | null>
> {
  const url = `${apiBaseUrl()}/api/v1/pipeline/jobs`;
  try {
    const response = await fetch(url, { cache: "no-store" });
    if (response.status === 404) {
      return { ok: true, data: null };
    }
    if (response.status === 503) {
      return {
        ok: false,
        status: 503,
        reason: "warehouse_busy",
        message: WAREHOUSE_BUSY_MESSAGE,
      };
    }
    if (!response.ok) {
      const message = await readErrorMessage(
        response,
        `API returned ${response.status}`,
      );
      return failFromResponse(response.status, message);
    }
    const data = (await response.json()) as PipelineJobStatus;
    return { ok: true, data };
  } catch {
    return {
      ok: false,
      status: null,
      reason: "api_down",
      message: API_DOWN_MESSAGE,
    };
  }
}

export function fetchAnalyses(params?: {
  limit?: number;
  offset?: number;
}): Promise<ApiResult<ListEnvelope<AnalysisItem>>> {
  return fetchJson(
    withQuery("/api/v1/analyses", {
      limit: params?.limit,
      offset: params?.offset,
    }),
  );
}

export function fetchAnalysis(
  analysisId: string,
): Promise<ApiResult<AnalysisItem>> {
  return fetchJson(`/api/v1/analyses/${encodeURIComponent(analysisId)}`);
}

export function createAnalysis(
  payload: AnalysisCreate,
): Promise<ApiResult<AnalysisItem>> {
  return postJson("/api/v1/analyses", {
    label: payload.label,
    notes: payload.notes ?? null,
  });
}

export function patchAnalysis(
  analysisId: string,
  payload: AnalysisUpdate,
): Promise<ApiResult<AnalysisItem>> {
  return patchJson(`/api/v1/analyses/${encodeURIComponent(analysisId)}`, payload);
}

export function fetchAnalysisIncidents(
  analysisId: string,
  params?: IncidentListParams,
): Promise<ApiResult<ListEnvelope<IncidentItem>>> {
  return fetchJson(
    withQuery(`/api/v1/analyses/${encodeURIComponent(analysisId)}/incidents`, {
      severity: params?.severity,
      entity_id: params?.entity_id,
      q: params?.q,
      start_after: params?.start_after,
      end_before: params?.end_before,
      detector: params?.detector,
      min_detectors: params?.min_detectors,
      disposition: params?.disposition,
      sort: params?.sort,
      order: params?.order,
      limit: params?.limit,
      offset: params?.offset,
    }),
  );
}

export function fetchAnalysisKpis(
  analysisId: string,
): Promise<ApiResult<IncidentKpis>> {
  return fetchJson(
    `/api/v1/analyses/${encodeURIComponent(analysisId)}/kpis`,
  );
}

export function fetchCopilotStatus(): Promise<ApiResult<CopilotStatus>> {
  return fetchJson("/api/v1/copilot/status");
}

export async function postCopilotChat(payload: {
  messages: CopilotChatMessage[];
  attachments?: CopilotAttachment[];
  incident_id?: string | null;
  analysis_id?: string | null;
}): Promise<ApiResult<CopilotChatResponse>> {
  const url = `${apiBaseUrl()}/api/v1/copilot/chat`;
  try {
    const response = await fetch(url, {
      method: "POST",
      cache: "no-store",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      const message = await readErrorMessage(
        response,
        `API returned ${response.status}`,
      );
      // Preserve server detail for disabled / provider-down (not warehouse busy).
      if (response.status === 503) {
        return {
          ok: false,
          status: 503,
          reason: "http_error",
          message,
        };
      }
      return failFromResponse(response.status, message);
    }
    const data = (await response.json()) as CopilotChatResponse;
    return { ok: true, data };
  } catch {
    return {
      ok: false,
      status: null,
      reason: "api_down",
      message: API_DOWN_MESSAGE,
    };
  }
}
