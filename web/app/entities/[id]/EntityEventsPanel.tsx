import { TableEntityTimeline } from "@/components/entity/TableEntityTimeline";
import { AlertApiDown } from "@/components/feedback/AlertApiDown";
import { AlertWarehouseBusy } from "@/components/feedback/AlertWarehouseBusy";
import { fetchEntityTimeline } from "@/lib/api";
import { EVENT_PAGE_SIZE, parsePage } from "@/lib/format";
import { entityEventsHref } from "@/lib/hrefs";
import type { TimelineEvent } from "@/lib/types";
import { resolveEntityWindow, type EntityWindowQuery } from "@/lib/window";

type EntityEventsPanelProps = {
  entityId: string;
  query: EntityWindowQuery & { page?: string };
};

export async function EntityEventsPanel({
  entityId,
  query,
}: EntityEventsPanelProps) {
  const window = resolveEntityWindow(query);
  const page = parsePage(query.page);
  const offset = (page - 1) * EVENT_PAGE_SIZE;
  const padHours = window.hasWindow ? window.padHours : undefined;
  const retryHref = entityEventsHref(
    entityId,
    window.startParam,
    window.endParam,
    padHours,
    page,
  );

  const timelineResult = await fetchEntityTimeline(entityId, {
    start: window.windowStart,
    end: window.windowEnd,
    order: window.order,
    limit: EVENT_PAGE_SIZE,
    offset,
  });

  if (!timelineResult.ok) {
    if (timelineResult.reason === "warehouse_busy" || timelineResult.reason === "warehouse_missing") {
      return <AlertWarehouseBusy retryHref={retryHref} />;
    }
    return <AlertApiDown />;
  }

  const timelineItems: TimelineEvent[] = timelineResult.data.items;

  return (
    <TableEntityTimeline
      items={timelineItems}
      newestFirst={window.newestFirst}
      total={timelineResult.data.total}
      offset={timelineResult.data.offset}
      hrefForPage={(nextPage) =>
        entityEventsHref(
          entityId,
          window.startParam,
          window.endParam,
          padHours,
          nextPage,
        )
      }
    />
  );
}
