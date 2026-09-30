import { notFound } from "next/navigation";
import { EntityAnalysisPanel } from "../EntityAnalysisPanel";
import { EntityEventsPanel } from "../EntityEventsPanel";
import { EntityOverviewPanel } from "../EntityOverviewPanel";

export const dynamic = "force-dynamic";

const VALID_SECTIONS = new Set(["analysis", "events"]);

type EntitySectionPageProps = {
  params: Promise<{ id: string; section?: string[] }>;
  searchParams: Promise<{
    start?: string;
    end?: string;
    pad_hours?: string;
    order?: string;
    page?: string;
  }>;
};

export default async function EntitySectionPage({
  params,
  searchParams,
}: EntitySectionPageProps) {
  const { id: rawId, section } = await params;
  const query = await searchParams;
  const entityId = decodeURIComponent(rawId);
  const tab = section?.[0];

  if (section && (section.length !== 1 || !VALID_SECTIONS.has(tab ?? ""))) {
    notFound();
  }

  if (tab === "analysis") {
    return <EntityAnalysisPanel entityId={entityId} query={query} />;
  }
  if (tab === "events") {
    return <EntityEventsPanel entityId={entityId} query={query} />;
  }

  return <EntityOverviewPanel entityId={entityId} query={query} />;
}
