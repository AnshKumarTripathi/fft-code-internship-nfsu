"use client";

import { SectionBlock } from "@/components/layout/SectionBlock";
import { formatUtc, jobStageBadgeClass } from "@/lib/format";
import type { PipelineJobStageItem } from "@/lib/types";

type TablePipelineStagesProps = {
  stages: PipelineJobStageItem[];
};

function stageDotClass(status: string): string {
  switch (status) {
    case "success":
      return "bg-success";
    case "running":
      return "bg-primary animate-pulse";
    case "failed":
      return "bg-error";
    case "skipped":
      return "bg-base-300";
    default:
      return "bg-base-300";
  }
}

export function TablePipelineStages({ stages }: TablePipelineStagesProps) {
  if (stages.length === 0) {
    return null;
  }

  return (
    <SectionBlock title="Stages">
      <ol className="flex flex-wrap items-center gap-2" aria-label="Stage strip">
        {stages.map((stage, index) => (
          <li key={stage.stage} className="flex items-center gap-2">
            {index > 0 ? (
              <span className="h-px w-3 bg-base-300" aria-hidden />
            ) : null}
            <span
              className={`inline-block h-2.5 w-2.5 rounded-full ${stageDotClass(stage.status)}`}
              title={`${stage.stage}: ${stage.status}`}
              aria-hidden
            />
            <span className="text-xs capitalize text-base-content/80">
              {stage.stage}
            </span>
          </li>
        ))}
      </ol>
      <div className="fft-paper-panel overflow-x-auto">
        <table className="table table-sm">
          <thead>
            <tr className="text-xs uppercase tracking-wide text-base-content/60">
              <th>Stage</th>
              <th>Status</th>
              <th>Detail</th>
              <th>Finished (UTC)</th>
            </tr>
          </thead>
          <tbody>
            {stages.map((stage) => (
              <tr key={stage.stage}>
                <td>
                  <code>{stage.stage}</code>
                </td>
                <td>
                  <span className={jobStageBadgeClass(stage.status)}>
                    {stage.status}
                  </span>
                </td>
                <td className="max-w-md text-sm text-base-content/80">
                  {stage.detail || "—"}
                </td>
                <td className="fft-mono-meta">{formatUtc(stage.finished_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </SectionBlock>
  );
}
