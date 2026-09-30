"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { fetchAnalysis, fetchLatestPipelineJob } from "@/lib/api";
import { isPipelineJobActive } from "@/lib/format";
import { pipelineHref } from "@/lib/hrefs";
import type { AnalysisItem, PipelineJobStatus } from "@/lib/types";

const POLL_MS = 2000;

type BannerPipelineJobProps = {
  /** When true, always show an Open pipeline link even if idle. */
  showIdleLink?: boolean;
};

export function BannerPipelineJob({
  showIdleLink = false,
}: BannerPipelineJobProps) {
  const [job, setJob] = useState<PipelineJobStatus | null>(null);
  const [analysis, setAnalysis] = useState<AnalysisItem | null>(null);
  const [checked, setChecked] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function poll() {
      const result = await fetchLatestPipelineJob();
      if (cancelled) {
        return;
      }
      if (result.ok) {
        setJob(result.data);
        const analysisId = result.data?.analysis_id;
        if (analysisId) {
          const analysisResult = await fetchAnalysis(analysisId);
          if (!cancelled && analysisResult.ok) {
            setAnalysis(analysisResult.data);
          }
        } else {
          setAnalysis(null);
        }
      }
      setChecked(true);
    }

    void poll();
    const timer = window.setInterval(() => {
      void poll();
    }, POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  const isActive = isPipelineJobActive(job?.status);
  if (!checked) {
    return null;
  }

  const analysisChrome = analysis?.label ? (
    <span>
      Analysis: <span className="font-medium">{analysis.label}</span>
      {analysis.status ? (
        <>
          {" "}
          (<span className="capitalize">{analysis.status}</span>)
        </>
      ) : null}
      . Live triage is not yet scoped to this container.
    </span>
  ) : (
    <span>No named analysis on the latest job yet.</span>
  );

  if (isActive && job) {
    const total = Math.max(job.total_stages, 1);
    const completed = Math.min(job.completed_stages, total);
    const shardLabel =
      job.mode === "run_sharded" &&
      job.shard_count != null &&
      job.shard_count > 0 &&
      job.shard_index != null
        ? ` · shard ${job.shard_index + 1}/${job.shard_count}`
        : "";
    return (
      <div role="status" className="alert alert-info">
        <div className="flex w-full flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex flex-col gap-1">
            <span>
              Pipeline:{" "}
              <span className="font-medium capitalize">{job.status}</span>
              {job.phase ? (
                <>
                  {" "}
                  — <code>{job.phase}</code>
                </>
              ) : job.current_stage ? (
                <>
                  {" "}
                  — <code>{job.current_stage}</code>
                </>
              ) : null}
              {shardLabel} ({completed}/{job.total_stages} stages)
            </span>
            <span className="text-sm">{analysisChrome}</span>
          </div>
          <Link className="btn btn-primary btn-sm" href={pipelineHref()}>
            Open pipeline
          </Link>
        </div>
      </div>
    );
  }

  if (showIdleLink) {
    return (
      <div className="fft-paper-panel flex flex-col gap-2 px-4 py-3 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-base-content/70">
            Start or watch a batch run from Pipeline (CLI{" "}
            <code>run-all</code> still works for power users).
          </span>
          <Link className="btn btn-primary btn-sm" href={pipelineHref()}>
            Pipeline
          </Link>
        </div>
        <p className="text-base-content/70">{analysisChrome}</p>
      </div>
    );
  }

  return null;
}
