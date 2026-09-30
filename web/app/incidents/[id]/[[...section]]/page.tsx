import { notFound } from "next/navigation";
import { IncidentAnalysisPanel } from "../IncidentAnalysisPanel";
import { IncidentEventsPanel } from "../IncidentEventsPanel";
import { IncidentOverviewPanel } from "../IncidentOverviewPanel";

export const dynamic = "force-dynamic";

const VALID_SECTIONS = new Set(["analysis", "events"]);

type IncidentSectionPageProps = {
  params: Promise<{ id: string; section?: string[] }>;
  searchParams: Promise<{
    page?: string;
    step?: string;
  }>;
};

export default async function IncidentSectionPage({
  params,
  searchParams,
}: IncidentSectionPageProps) {
  const { id: rawId, section } = await params;
  const query = await searchParams;
  const incidentId = decodeURIComponent(rawId);
  const tab = section?.[0];

  if (section && (section.length !== 1 || !VALID_SECTIONS.has(tab ?? ""))) {
    notFound();
  }

  if (tab === "analysis") {
    return <IncidentAnalysisPanel incidentId={incidentId} />;
  }
  if (tab === "events") {
    return <IncidentEventsPanel incidentId={incidentId} query={query} />;
  }

  return <IncidentOverviewPanel incidentId={incidentId} />;
}
