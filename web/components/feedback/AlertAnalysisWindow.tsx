import Link from "next/link";
import { fetchPipelineShardingSettings } from "@/lib/api";
import { docsConfigKnobsHref } from "@/lib/docs-links";

/** Honesty banner when detectors scored a bounded slice of merged history. */
export async function AlertAnalysisWindow() {
  const result = await fetchPipelineShardingSettings();
  if (!result.ok || !result.data.analysis_window_enabled) {
    return null;
  }

  const days = result.data.analysis_window_last_days ?? 30;
  const start = result.data.analysis_window_start_utc;
  const end = result.data.analysis_window_end_utc;
  const bound =
    start && end
      ? `absolute UTC ${start} → ${end}`
      : `last ${days} days of merged history`;

  return (
    <div role="note" className="alert alert-info text-sm">
      <span>
        Detectors used {bound}; raw events and buckets outside that window may
        still exist in the warehouse for review. STFT caps still apply.{" "}
        <Link className="link" href={docsConfigKnobsHref()}>
          Config knobs
        </Link>
      </span>
    </div>
  );
}
