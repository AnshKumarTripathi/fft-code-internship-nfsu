import Link from "next/link";
import { TableEntityIncidents } from "@/components/entity/TableEntityIncidents";
import { AlertApiDown } from "@/components/feedback/AlertApiDown";
import { AlertWarehouseBusy } from "@/components/feedback/AlertWarehouseBusy";
import { fetchEntityIncidents, fetchEntityTimeline } from "@/lib/api";
import {
  entityAnalysisHref,
  entityEventsHref,
  entityHref,
} from "@/lib/hrefs";
import type { IncidentItem } from "@/lib/types";
import { resolveEntityWindow, type EntityWindowQuery } from "@/lib/window";

type EntityOverviewPanelProps = {
  entityId: string;
  query: EntityWindowQuery & { page?: string };
};

export async function EntityOverviewPanel({
  entityId,
  query,
}: EntityOverviewPanelProps) {
  const window = resolveEntityWindow(query);
  const retryHref = entityHref(
    entityId,
    window.startParam,
    window.endParam,
    window.hasWindow ? window.padHours : undefined,
  );

  const [incidentsResult, timelineResult] = await Promise.all([
    fetchEntityIncidents(entityId),
    fetchEntityTimeline(entityId, {
      start: window.windowStart,
      end: window.windowEnd,
      order: window.order,
      limit: 1,
      offset: 0,
    }),
  ]);

  if (!incidentsResult.ok) {
    if (incidentsResult.reason === "warehouse_busy" || incidentsResult.reason === "warehouse_missing") {
      return <AlertWarehouseBusy retryHref={retryHref} />;
    }
    return <AlertApiDown />;
  }

  const incidentItems: IncidentItem[] = incidentsResult.data.items;
  const eventTotal = timelineResult.ok ? timelineResult.data.total : 0;
  const padHours = window.hasWindow ? window.padHours : undefined;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap gap-2">
        <Link
          className="btn btn-sm"
          href={entityAnalysisHref(
            entityId,
            window.startParam,
            window.endParam,
            padHours,
          )}
        >
          Open analysis
        </Link>
        <Link
          className="btn btn-sm btn-primary"
          href={entityEventsHref(
            entityId,
            window.startParam,
            window.endParam,
            padHours,
          )}
        >
          Browse events ({eventTotal})
        </Link>
      </div>
      <TableEntityIncidents items={incidentItems} />
    </div>
  );
}
