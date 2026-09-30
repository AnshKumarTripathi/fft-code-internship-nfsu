import { redirect } from "next/navigation";
import { pipelineHref } from "@/lib/hrefs";

export const dynamic = "force-dynamic";

/** Phase 64: keep `/pipeline` bookmarks working; home owns the UI. */
export default function PipelineRedirectPage() {
  redirect(pipelineHref());
}
