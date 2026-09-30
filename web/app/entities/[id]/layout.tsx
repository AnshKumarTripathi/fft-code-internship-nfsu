import { Suspense } from "react";
import { AlertApiDown } from "@/components/feedback/AlertApiDown";
import { AlertLoading } from "@/components/feedback/AlertLoading";
import { AlertEntityNotFound } from "@/components/feedback/AlertEntityNotFound";
import { AlertWarehouseBusy } from "@/components/feedback/AlertWarehouseBusy";
import { CardEntityMeta } from "@/components/entity/CardEntityMeta";
import { FormEntityWindow } from "@/components/entity/FormEntityWindow";
import { NavInvestigationTabs } from "@/components/layout/NavInvestigationTabs";
import { fetchEntity } from "@/lib/api";
import { entityHref } from "@/lib/hrefs";

export const dynamic = "force-dynamic";

type EntityLayoutProps = {
  children: React.ReactNode;
  params: Promise<{ id: string }>;
};

export default async function EntityLayout({
  children,
  params,
}: EntityLayoutProps) {
  const { id: rawId } = await params;
  const entityId = decodeURIComponent(rawId);
  const retryHref = entityHref(entityId);

  const entityResult = await fetchEntity(entityId);
  if (!entityResult.ok) {
    if (entityResult.status === 404) {
      return <AlertEntityNotFound />;
    }
    if (entityResult.reason === "warehouse_busy" || entityResult.reason === "warehouse_missing") {
      return <AlertWarehouseBusy retryHref={retryHref} />;
    }
    return <AlertApiDown />;
  }

  const basePath = `/entities/${encodeURIComponent(entityId)}`;

  return (
    <div className="flex flex-col gap-6">
      <CardEntityMeta entity={entityResult.data} />
      <Suspense fallback={<AlertLoading label="Loading entity window…" />}>
        <FormEntityWindow />
        <NavInvestigationTabs basePath={basePath} />
      </Suspense>
      {children}
    </div>
  );
}
