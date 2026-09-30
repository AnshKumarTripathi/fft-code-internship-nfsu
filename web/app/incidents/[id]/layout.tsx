import { Suspense } from "react";
import { AlertApiDown } from "@/components/feedback/AlertApiDown";
import { AlertIncidentNotFound } from "@/components/feedback/AlertIncidentNotFound";
import { AlertLoading } from "@/components/feedback/AlertLoading";
import { AlertWarehouseBusy } from "@/components/feedback/AlertWarehouseBusy";
import { CardIncidentHeader } from "@/components/incident/CardIncidentHeader";
import { NavInvestigationTabs } from "@/components/layout/NavInvestigationTabs";
import { fetchEntity, fetchIncident } from "@/lib/api";
import { incidentHref } from "@/lib/hrefs";
import type { EntityMeta } from "@/lib/types";

export const dynamic = "force-dynamic";

type IncidentLayoutProps = {
  children: React.ReactNode;
  params: Promise<{ id: string }>;
};

export default async function IncidentLayout({
  children,
  params,
}: IncidentLayoutProps) {
  const { id: rawId } = await params;
  const incidentId = decodeURIComponent(rawId);
  const retryHref = incidentHref(incidentId);

  const incidentResult = await fetchIncident(incidentId);
  if (!incidentResult.ok) {
    if (incidentResult.status === 404) {
      return <AlertIncidentNotFound />;
    }
    if (incidentResult.reason === "warehouse_busy" || incidentResult.reason === "warehouse_missing") {
      return <AlertWarehouseBusy retryHref={retryHref} />;
    }
    return <AlertApiDown />;
  }

  const incident = incidentResult.data;
  const entityResult = await fetchEntity(incident.entity_id);
  const entity: EntityMeta | null = entityResult.ok ? entityResult.data : null;
  const basePath = `/incidents/${encodeURIComponent(incidentId)}`;

  return (
    <div className="flex flex-col gap-6">
      <CardIncidentHeader incident={incident} entity={entity} />
      <Suspense fallback={<AlertLoading label="Loading investigation tabs…" />}>
        <NavInvestigationTabs basePath={basePath} />
      </Suspense>
      {children}
    </div>
  );
}
