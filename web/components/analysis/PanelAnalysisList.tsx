"use client";

import { useEffect, useState } from "react";
import { CardAnalysisSummary } from "@/components/analysis/CardAnalysisSummary";
import { SectionBlock } from "@/components/layout/SectionBlock";
import { fetchAnalyses } from "@/lib/api";
import type { AnalysisItem } from "@/lib/types";

type PanelAnalysisListProps = {
  activeAnalysisId?: string | null;
  refreshKey?: number;
  onContinue?: (analysis: AnalysisItem) => void;
  onLoaded?: (items: AnalysisItem[]) => void;
};

export function PanelAnalysisList({
  activeAnalysisId = null,
  refreshKey = 0,
  onContinue,
  onLoaded,
}: PanelAnalysisListProps) {
  const [items, setItems] = useState<AnalysisItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState("");

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const result = await fetchAnalyses({ limit: 50, offset: 0 });
      if (cancelled) {
        return;
      }
      setIsLoading(false);
      if (!result.ok) {
        setErrorMessage(result.message);
        return;
      }
      setErrorMessage("");
      setItems(result.data.items);
      onLoaded?.(result.data.items);
    })();
    return () => {
      cancelled = true;
    };
  }, [refreshKey, onLoaded]);

  async function handleRefresh() {
    setIsLoading(true);
    const result = await fetchAnalyses({ limit: 50, offset: 0 });
    setIsLoading(false);
    if (!result.ok) {
      setErrorMessage(result.message);
      return;
    }
    setErrorMessage("");
    setItems(result.data.items);
    onLoaded?.(result.data.items);
  }

  return (
    <SectionBlock
      title="Analyses"
      description="Named corpus runs. Each Start binds a container; Open triage loads that analysis’s snapshot. Live warehouse still refreshes on re-run."
      actions={
        <button
          type="button"
          className="btn btn-ghost btn-sm"
          onClick={() => void handleRefresh()}
          disabled={isLoading}
        >
          Refresh
        </button>
      }
    >
      {errorMessage ? (
        <div role="alert" className="alert alert-warning">
          <span>{errorMessage}</span>
        </div>
      ) : null}

      {isLoading && items.length === 0 ? (
        <div role="status" className="alert">
          <span className="loading loading-spinner loading-sm" />
          <span>Loading analyses…</span>
        </div>
      ) : null}

      {!isLoading && items.length === 0 && !errorMessage ? (
        <p className="text-sm text-base-content/70">
          No analyses yet. Enter a label below and start a run to create the
          first container.
        </p>
      ) : null}

      {items.length > 0 ? (
        <div className="grid gap-4 sm:grid-cols-2">
          {items.map((analysis) => (
            <CardAnalysisSummary
              key={analysis.analysis_id}
              analysis={analysis}
              isActive={analysis.analysis_id === activeAnalysisId}
              onContinue={onContinue}
            />
          ))}
        </div>
      ) : null}
    </SectionBlock>
  );
}
