import { BannerGuidedSteps } from "@/components/feedback/BannerGuidedSteps";
import { PageHeader } from "@/components/layout/PageHeader";
import { PanelPipelineOperator } from "@/components/pipeline/PanelPipelineOperator";

export const dynamic = "force-dynamic";

/** Phase 64–68: Pipeline + analyses + Lab Paper shell. */
export default function HomePipelinePage() {
  return (
    <div className="fft-page">
      <PageHeader
        eyebrow="Operator pipeline"
        title="Pipeline"
        blurb={
          <>
            Name an analysis, stage logs, and start the same batch chain as CLI{" "}
            <code>run-all</code>. Each start binds a corpus digest and job to that
            container. Only one job runs at a time; mid-run cancel is not
            available. After correlate finishes, open Triage to review incidents.
          </>
        }
      />
      <BannerGuidedSteps />
      <PanelPipelineOperator />
    </div>
  );
}
