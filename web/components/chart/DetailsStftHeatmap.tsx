"use client";

import { useEffect, useState } from "react";
import { ChartEntityStftHeatmap } from "@/components/chart/ChartEntityStftHeatmap";
import { DetailsSpectral } from "@/components/layout/DetailsSpectral";
import { fetchEntityStft } from "@/lib/api";
import type { StftMatrixResponse } from "@/lib/types";

type DetailsStftHeatmapProps = {
  entityId: string;
  start?: string | null;
  end?: string | null;
};

export function DetailsStftHeatmap({
  entityId,
  start,
  end,
}: DetailsStftHeatmapProps) {
  const [matrix, setMatrix] = useState<StftMatrixResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [hasOpened, setHasOpened] = useState(false);

  useEffect(() => {
    if (!hasOpened) {
      return;
    }
    let cancelled = false;
    void (async () => {
      const result = await fetchEntityStft(entityId, {
        start: start ?? undefined,
        end: end ?? undefined,
      });
      if (cancelled) {
        return;
      }
      setIsLoading(false);
      if (!result.ok) {
        setErrorMessage(result.message);
        setMatrix(null);
        return;
      }
      setErrorMessage("");
      setMatrix(result.data);
    })();
    return () => {
      cancelled = true;
    };
  }, [entityId, start, end, hasOpened]);

  return (
    <DetailsSpectral
      summary="Show STFT heatmap"
      onOpenChange={(open) => {
        if (open) {
          setHasOpened(true);
          setIsLoading(true);
          setErrorMessage("");
        }
      }}
    >
      {isLoading ? (
        <div role="status" className="alert">
          <span className="loading loading-spinner loading-sm" />
          <span>Computing capped STFT matrix…</span>
        </div>
      ) : null}
      {errorMessage ? (
        <div role="alert" className="alert alert-error">
          <span>{errorMessage}</span>
        </div>
      ) : null}
      {matrix ? <ChartEntityStftHeatmap matrix={matrix} /> : null}
    </DetailsSpectral>
  );
}
