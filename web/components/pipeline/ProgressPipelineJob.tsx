"use client";

import { SectionBlock } from "@/components/layout/SectionBlock";
import { formatUtc, isPipelineJobActive, shortId } from "@/lib/format";
import type { PipelineJobStatus } from "@/lib/types";

type ProgressPipelineJobProps = {
  job: PipelineJobStatus | null;
  analysisLabel?: string | null;
};

export function ProgressPipelineJob({
  job,
  analysisLabel = null,
}: ProgressPipelineJobProps) {
  if (!job) {
    return (
      <SectionBlock
        title="Job progress"
        description="No job started from this API process yet. Name an analysis and start a run after staging files."
      >
        {null}
      </SectionBlock>
    );
  }

  const total = Math.max(job.total_stages, 1);
  const completed = Math.min(job.completed_stages, total);
  const percent = Math.round((completed / total) * 100);
  const isActive = isPipelineJobActive(job.status);
  const isSharded = job.mode === "run_sharded";
  const shardCount = job.shard_count ?? null;
  const shardIndex = job.shard_index;
  const shardLabel =
    isSharded &&
    shardCount != null &&
    shardCount > 0 &&
    shardIndex != null
      ? `Shard ${shardIndex + 1}/${shardCount}`
      : isSharded && shardCount != null && shardCount > 0
        ? `Shards: ${shardCount}`
        : null;

  return (
    <SectionBlock title="Job progress">
      {analysisLabel ? (
        <p className="text-sm">
          Analysis: <span className="font-medium">{analysisLabel}</span>
        </p>
      ) : null}
      <div className="flex flex-wrap items-center gap-3 text-sm">
        <span>
          Status: <span className="font-medium capitalize">{job.status}</span>
        </span>
        {isSharded && job.phase ? (
          <span>
            Phase: <code>{job.phase}</code>
          </span>
        ) : null}
        {shardLabel ? <span>{shardLabel}</span> : null}
        <span>
          Stages: {completed}/{job.total_stages}
        </span>
        {job.current_stage ? (
          <span>
            Current: <code>{job.current_stage}</code>
          </span>
        ) : null}
        <span className="text-base-content/70">
          Started: <span className="fft-mono-meta">{formatUtc(job.started_at)}</span>
        </span>
        {job.finished_at ? (
          <span className="text-base-content/70">
            Finished:{" "}
            <span className="fft-mono-meta">{formatUtc(job.finished_at)}</span>
          </span>
        ) : null}
        <span className="fft-mono-meta" title={job.job_id}>
          job {shortId(job.job_id)}
        </span>
      </div>
      <progress
        className={`progress w-full ${isActive ? "progress-primary" : job.status === "succeeded" ? "progress-success" : job.status === "failed" || job.status === "cancelled" ? "progress-error" : ""}`}
        value={completed}
        max={total}
        aria-valuenow={completed}
        aria-valuemin={0}
        aria-valuemax={total}
        aria-label={`Pipeline progress ${percent}%`}
      />
      {job.error ? (
        <div role="alert" className="alert alert-error">
          <span>{job.error}</span>
        </div>
      ) : null}
    </SectionBlock>
  );
}
