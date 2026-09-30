"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { PanelAnalysisList } from "@/components/analysis/PanelAnalysisList";
import { AlertApiDown } from "@/components/feedback/AlertApiDown";
import { AlertWarehouseBusy } from "@/components/feedback/AlertWarehouseBusy";
import { SectionBlock } from "@/components/layout/SectionBlock";
import { PanelLabReset } from "@/components/pipeline/PanelLabReset";
import { PanelLargeCorpus } from "@/components/pipeline/PanelLargeCorpus";
import { PanelPipelineUpload } from "@/components/pipeline/PanelPipelineUpload";
import { ProgressPipelineJob } from "@/components/pipeline/ProgressPipelineJob";
import { TablePipelineStages } from "@/components/pipeline/TablePipelineStages";
import { LinkDocsMore } from "@/components/docs/LinkDocsMore";
import { docsTroubleshootingHref } from "@/lib/docs-links";
import {
  cancelPipelineJob,
  createPipelineJob,
  deletePipelineUpload,
  fetchAnalysis,
  fetchLatestPipelineJob,
  fetchPipelineCorpusRaw,
  fetchPipelineJob,
  fetchPipelineShardingSettings,
  fetchPipelineUploads,
  seedDemoCorpus,
  uploadPipelineFiles,
} from "@/lib/api";
import { isPipelineJobActive, shortId } from "@/lib/format";
import { analysisTriageHref, incidentListHref, pipelineHref, runsHref } from "@/lib/hrefs";
import type {
  AnalysisItem,
  PipelineCorpusListResponse,
  PipelineJobStatus,
  PipelineShardingSettings,
  PipelineUploadFileItem,
} from "@/lib/types";

const POLL_MS = 1500;

export function PanelPipelineOperator() {
  const [files, setFiles] = useState<PipelineUploadFileItem[]>([]);
  const [uploadDir, setUploadDir] = useState<string | null>(null);
  const [job, setJob] = useState<PipelineJobStatus | null>(null);
  const [activeAnalysis, setActiveAnalysis] = useState<AnalysisItem | null>(
    null,
  );
  const [selectedAnalysisId, setSelectedAnalysisId] = useState<string | null>(
    null,
  );
  const [label, setLabel] = useState("");
  const [notes, setNotes] = useState("");
  const [listRefreshKey, setListRefreshKey] = useState(0);
  const [isBooting, setIsBooting] = useState(true);
  const [isUploading, setIsUploading] = useState(false);
  const [isSeeding, setIsSeeding] = useState(false);
  const [isStarting, setIsStarting] = useState(false);
  const [isCancelling, setIsCancelling] = useState(false);
  const [mlEnsembleEnabled, setMlEnsembleEnabled] = useState(false);
  const [uploadError, setUploadError] = useState("");
  const [actionError, setActionError] = useState("");
  const [apiDown, setApiDown] = useState(false);
  const [warehouseBusy, setWarehouseBusy] = useState(false);
  const [sharding, setSharding] = useState<PipelineShardingSettings | null>(
    null,
  );
  const [largeCorpusMode, setLargeCorpusMode] = useState(false);
  const [inputPath, setInputPath] = useState("");
  const [useStagedUploads, setUseStagedUploads] = useState(false);
  const [corpus, setCorpus] = useState<PipelineCorpusListResponse | null>(null);

  const isJobRunning = isPipelineJobActive(job?.status);

  const refreshUploads = useCallback(async () => {
    const result = await fetchPipelineUploads();
    if (!result.ok) {
      if (result.reason === "api_down") {
        setApiDown(true);
        return;
      }
      if (result.reason === "warehouse_busy" || result.reason === "warehouse_missing") {
        setWarehouseBusy(true);
        return;
      }
      setUploadError(result.message);
      return;
    }
    setApiDown(false);
    setWarehouseBusy(false);
    setFiles(result.data.files);
    setUploadDir(result.data.upload_dir);
    setUploadError("");
  }, []);

  const refreshCorpus = useCallback(async () => {
    const result = await fetchPipelineCorpusRaw();
    if (!result.ok) {
      if (result.reason === "api_down") {
        setApiDown(true);
      }
      return;
    }
    setCorpus(result.data);
  }, []);

  const loadAnalysis = useCallback(async (analysisId: string | null) => {
    if (!analysisId) {
      setActiveAnalysis(null);
      return;
    }
    const result = await fetchAnalysis(analysisId);
    if (result.ok) {
      setActiveAnalysis(result.data);
      setSelectedAnalysisId(result.data.analysis_id);
      setLabel(result.data.label);
      setNotes(result.data.notes ?? "");
    }
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function boot() {
      setIsBooting(true);
      const [uploadsResult, latestResult, shardingResult, corpusResult] =
        await Promise.all([
          fetchPipelineUploads(),
          fetchLatestPipelineJob(),
          fetchPipelineShardingSettings(),
          fetchPipelineCorpusRaw(),
        ]);
      if (cancelled) {
        return;
      }

      if (!uploadsResult.ok) {
        if (uploadsResult.reason === "api_down") {
          setApiDown(true);
        } else if (uploadsResult.reason === "warehouse_busy") {
          setWarehouseBusy(true);
        } else {
          setUploadError(uploadsResult.message);
        }
      } else {
        setFiles(uploadsResult.data.files);
        setUploadDir(uploadsResult.data.upload_dir);
      }

      if (shardingResult.ok) {
        setSharding(shardingResult.data);
      }

      if (corpusResult.ok) {
        setCorpus(corpusResult.data);
      }

      if (!latestResult.ok) {
        if (latestResult.reason === "api_down") {
          setApiDown(true);
        } else if (latestResult.reason === "warehouse_busy") {
          setWarehouseBusy(true);
        }
      } else if (latestResult.data) {
        setJob(latestResult.data);
        if (latestResult.data.analysis_id) {
          await loadAnalysis(latestResult.data.analysis_id);
        }
      }

      setIsBooting(false);
    }

    void boot();
    return () => {
      cancelled = true;
    };
  }, [loadAnalysis]);

  useEffect(() => {
    if (!job || !isPipelineJobActive(job.status)) {
      return;
    }
    const jobId = job.job_id;
    const timer = window.setInterval(() => {
      void (async () => {
        const result = await fetchPipelineJob(jobId);
        if (!result.ok) {
          if (result.reason === "api_down") {
            setApiDown(true);
          }
          return;
        }
        setJob(result.data);
        if (
          result.data.status === "succeeded" ||
          result.data.status === "failed" ||
          result.data.status === "cancelled"
        ) {
          if (result.data.analysis_id) {
            await loadAnalysis(result.data.analysis_id);
          }
          setListRefreshKey((value) => value + 1);
          setIsCancelling(false);
        }
      })();
    }, POLL_MS);
    return () => window.clearInterval(timer);
  }, [job?.job_id, job?.status, loadAnalysis]);

  async function onUpload(selected: File[]) {
    if (selected.length === 0 || isJobRunning) {
      return;
    }
    setIsUploading(true);
    setUploadError("");
    const result = await uploadPipelineFiles(selected);
    setIsUploading(false);
    if (!result.ok) {
      if (result.reason === "api_down") {
        setApiDown(true);
        return;
      }
      setUploadError(result.message);
      return;
    }
    await refreshUploads();
  }

  async function onDelete(name: string) {
    if (isJobRunning) {
      return;
    }
    setUploadError("");
    const result = await deletePipelineUpload(name);
    if (!result.ok) {
      if (result.reason === "api_down") {
        setApiDown(true);
        return;
      }
      setUploadError(result.message);
      return;
    }
    await refreshUploads();
  }

  async function onSeedDemo() {
    if (isJobRunning) {
      return;
    }
    setIsSeeding(true);
    setUploadError("");
    const result = await seedDemoCorpus();
    setIsSeeding(false);
    if (!result.ok) {
      if (result.reason === "api_down") {
        setApiDown(true);
        return;
      }
      setUploadError(result.message);
      return;
    }
    await refreshUploads();
  }

  function onContinue(analysis: AnalysisItem) {
    setSelectedAnalysisId(analysis.analysis_id);
    setActiveAnalysis(analysis);
    setLabel(analysis.label);
    setNotes(analysis.notes ?? "");
    setActionError("");
  }

  async function onStartRun() {
    const trimmed = label.trim();
    if (!trimmed && !selectedAnalysisId) {
      setActionError("Enter an analysis label before starting a run.");
      return;
    }
    setIsStarting(true);
    setActionError("");
    const result = await createPipelineJob(
      largeCorpusMode
        ? {
            mode: "run_sharded",
            analysis_id: selectedAnalysisId,
            label: selectedAnalysisId ? null : trimmed,
            notes: selectedAnalysisId ? null : notes.trim() || null,
            ml_ensemble_enabled: mlEnsembleEnabled,
            input_path: useStagedUploads ? null : inputPath.trim() || null,
            use_staged_uploads: useStagedUploads,
          }
        : {
            mode: "run_all",
            analysis_id: selectedAnalysisId,
            label: selectedAnalysisId ? null : trimmed,
            notes: selectedAnalysisId ? null : notes.trim() || null,
            ml_ensemble_enabled: mlEnsembleEnabled,
          },
    );
    setIsStarting(false);
    if (!result.ok) {
      if (result.reason === "api_down") {
        setApiDown(true);
        return;
      }
      if (result.reason === "warehouse_busy" || result.reason === "warehouse_missing") {
        setWarehouseBusy(true);
        setActionError(result.message);
        return;
      }
      setActionError(result.message);
      return;
    }
    setWarehouseBusy(false);
    setJob(result.data);
    if (result.data.analysis_id) {
      setSelectedAnalysisId(result.data.analysis_id);
      await loadAnalysis(result.data.analysis_id);
    }
    setListRefreshKey((value) => value + 1);
  }

  async function onCancelRun() {
    if (!job || !job.cancel_supported || !isJobRunning) {
      return;
    }
    setIsCancelling(true);
    setActionError("");
    const result = await cancelPipelineJob(job.job_id);
    if (!result.ok) {
      setIsCancelling(false);
      if (result.reason === "api_down") {
        setApiDown(true);
        return;
      }
      setActionError(result.message);
      return;
    }
    setJob(result.data);
  }

  if (apiDown) {
    return <AlertApiDown />;
  }

  if (warehouseBusy && !job) {
    return <AlertWarehouseBusy retryHref={pipelineHref()} />;
  }

  if (isBooting) {
    return (
      <div role="status" className="alert">
        <span className="loading loading-spinner loading-sm" />
        <span>Loading pipeline controls…</span>
      </div>
    );
  }

  const hasShardedSource = useStagedUploads
    ? files.length === 1
    : Boolean(inputPath.trim());
  const canStartNormal =
    !isJobRunning &&
    !isStarting &&
    !isUploading &&
    !isSeeding &&
    files.length > 0 &&
    (Boolean(label.trim()) || Boolean(selectedAnalysisId));
  const canStartSharded =
    !isJobRunning &&
    !isStarting &&
    !isUploading &&
    !isSeeding &&
    hasShardedSource &&
    (Boolean(label.trim()) || Boolean(selectedAnalysisId));
  const canStart = largeCorpusMode ? canStartSharded : canStartNormal;
  const canCancel =
    Boolean(job?.cancel_supported) &&
    isJobRunning &&
    !isCancelling &&
    !job?.cancel_requested;

  return (
    <div className="flex flex-col gap-8">
      {warehouseBusy ? (
        <AlertWarehouseBusy retryHref={pipelineHref()} />
      ) : null}

      <SectionBlock
        title="Name this analysis"
        description="Required for a new run. Use Continue on a card to re-bind an existing draft or failed container."
      >
        <label className="form-control w-full max-w-xl">
          <span className="label-text text-sm">Label</span>
          <input
            type="text"
            className="input input-bordered input-sm w-full"
            value={label}
            disabled={isJobRunning}
            maxLength={200}
            placeholder="SSH lab · Mar 5 afternoon"
            onChange={(event) => {
              setLabel(event.target.value);
              if (selectedAnalysisId) {
                setSelectedAnalysisId(null);
              }
            }}
          />
        </label>
        <label className="form-control w-full max-w-xl">
          <span className="label-text text-sm">Notes (optional)</span>
          <textarea
            className="textarea textarea-bordered w-full"
            rows={2}
            value={notes}
            disabled={isJobRunning || Boolean(selectedAnalysisId)}
            maxLength={2000}
            placeholder="Corpus notes for mentors"
            onChange={(event) => setNotes(event.target.value)}
          />
        </label>
        {selectedAnalysisId ? (
          <p className="text-sm text-base-content/70">
            Continuing analysis{" "}
            <span className="fft-mono-meta" title={selectedAnalysisId}>
              {shortId(selectedAnalysisId)}
            </span>
            . Edit the label to start a new container instead.
          </p>
        ) : null}
      </SectionBlock>

      <PanelAnalysisList
        activeAnalysisId={
          activeAnalysis?.analysis_id ?? selectedAnalysisId ?? job?.analysis_id
        }
        refreshKey={listRefreshKey}
        onContinue={onContinue}
      />

      <PanelPipelineUpload
        files={files}
        uploadDir={uploadDir}
        disabled={isJobRunning}
        isUploading={isUploading}
        isSeeding={isSeeding}
        errorMessage={uploadError}
        onUpload={onUpload}
        onDelete={onDelete}
        onSeedDemo={onSeedDemo}
        onRefresh={() => void refreshUploads()}
      />

      <PanelLargeCorpus
        enabled={Boolean(sharding?.enabled)}
        settings={sharding}
        largeCorpusMode={largeCorpusMode}
        onLargeCorpusModeChange={setLargeCorpusMode}
        inputPath={inputPath}
        onInputPathChange={setInputPath}
        useStagedUploads={useStagedUploads}
        onUseStagedUploadsChange={setUseStagedUploads}
        corpus={corpus}
        stagedFiles={files}
        disabled={isJobRunning}
        onRefreshCorpus={() => void refreshCorpus()}
      />

      <SectionBlock title="Start run">
        <label className="label cursor-pointer justify-start gap-3 py-0">
          <input
            type="checkbox"
            className="toggle toggle-sm"
            checked={mlEnsembleEnabled}
            disabled={isJobRunning || isStarting}
            onChange={(event) => setMlEnsembleEnabled(event.target.checked)}
          />
          <span className="label-text text-sm">
            ML ensemble (IsolationForest + autoencoder, majority vote)
          </span>
        </label>
        <p className="text-sm text-base-content/70">
          Off by default (IsolationForest only). Enable for stricter ML flags —
          both models must agree.
        </p>
        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            className="btn btn-primary"
            disabled={!canStart}
            aria-busy={isStarting || isJobRunning}
            onClick={() => void onStartRun()}
          >
            {isStarting || isJobRunning ? (
              <>
                <span className="loading loading-spinner loading-sm" />
                {isJobRunning
                  ? largeCorpusMode || job?.mode === "run_sharded"
                    ? "Sharded run…"
                    : "Running…"
                  : "Starting…"}
              </>
            ) : largeCorpusMode ? (
              "Start sharded run"
            ) : (
              "Start run"
            )}
          </button>
          {canCancel ? (
            <button
              type="button"
              className="btn btn-outline btn-warning"
              disabled={isCancelling}
              onClick={() => void onCancelRun()}
            >
              {isCancelling || job?.cancel_requested
                ? "Stopping after shard…"
                : "Stop after current shard"}
            </button>
          ) : null}
          {!largeCorpusMode && files.length === 0 ? (
            <span className="text-sm text-base-content/70">
              Stage at least one file before starting.
            </span>
          ) : null}
          {largeCorpusMode && !hasShardedSource ? (
            <span className="text-sm text-base-content/70">
              Set a server path or stage exactly one file.
            </span>
          ) : null}
        </div>
        {actionError ? (
          <div role="alert" className="alert alert-warning">
            <span>
              {actionError}{" "}
              <LinkDocsMore href={docsTroubleshootingHref()}>
                Troubleshooting
              </LinkDocsMore>
            </span>
          </div>
        ) : null}

        <ProgressPipelineJob
          job={job}
          analysisLabel={activeAnalysis?.label ?? null}
        />
        <TablePipelineStages stages={job?.stages ?? []} />

        {job?.status === "succeeded" ? (
          <div className="flex flex-wrap gap-2">
            <Link
              className="btn btn-primary"
              href={
                job.analysis_id
                  ? analysisTriageHref(job.analysis_id, { disposition: "any" })
                  : incidentListHref({ disposition: "open" })
              }
            >
              Open triage
            </Link>
            <Link className="btn btn-ghost" href={runsHref()}>
              View runs
            </Link>
          </div>
        ) : null}

        {job?.status === "failed" || job?.status === "cancelled" ? (
          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              className="btn btn-primary"
              disabled={!canStart}
              onClick={() => void onStartRun()}
            >
              Retry
            </button>
            <Link className="btn btn-ghost" href={runsHref()}>
              View runs
            </Link>
          </div>
        ) : null}
      </SectionBlock>

      <PanelLabReset
        disabled={isJobRunning || isStarting || isUploading || isSeeding}
        onCleared={async () => {
          setJob(null);
          setActiveAnalysis(null);
          setSelectedAnalysisId(null);
          setLabel("");
          setNotes("");
          setActionError("");
          setWarehouseBusy(false);
          setListRefreshKey((value) => value + 1);
          await refreshUploads();
          await refreshCorpus();
        }}
      />
    </div>
  );
}
