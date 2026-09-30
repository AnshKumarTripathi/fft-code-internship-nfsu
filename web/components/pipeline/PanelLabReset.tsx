"use client";

import { useState } from "react";
import { SectionBlock } from "@/components/layout/SectionBlock";
import { resetLabData } from "@/lib/api";

type PanelLabResetProps = {
  disabled: boolean;
  onCleared: () => void | Promise<void>;
};

export function PanelLabReset({ disabled, onCleared }: PanelLabResetProps) {
  const [isClearing, setIsClearing] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const [successMessage, setSuccessMessage] = useState("");
  const [clearUploads, setClearUploads] = useState(true);

  async function handleClear() {
    const ok = window.confirm(
      [
        "Clear lab data?",
        "",
        "This deletes the warehouse, analyses, reports, scores, parsed/timeseries,",
        "baselines, and in-memory job history.",
        clearUploads
          ? "Staged uploads under data/raw/uploads will also be removed."
          : "Staged uploads will be kept.",
        "",
        "Config, fixtures, and source code are not touched.",
        "A running pipeline job will block this action.",
      ].join("\n"),
    );
    if (!ok) {
      return;
    }
    setIsClearing(true);
    setErrorMessage("");
    setSuccessMessage("");
    const result = await resetLabData({
      confirm: "CLEAR",
      clear_uploads: clearUploads,
      clear_raw_non_upload: false,
    });
    setIsClearing(false);
    if (!result.ok) {
      setErrorMessage(result.message);
      return;
    }
    setSuccessMessage(result.data.message);
    await onCleared();
  }

  return (
    <SectionBlock
      title="Clear lab data"
      description="Remove prior runs and regenerable outputs so the next Start is a clean lab. Does not delete config or test fixtures."
    >
      <label className="flex cursor-pointer items-center gap-2 text-sm">
        <input
          type="checkbox"
          className="checkbox checkbox-sm"
          checked={clearUploads}
          disabled={disabled || isClearing}
          onChange={(event) => setClearUploads(event.target.checked)}
        />
        Also delete staged uploads (data/raw/uploads)
      </label>
      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          className="btn btn-error btn-outline btn-sm"
          disabled={disabled || isClearing}
          aria-busy={isClearing}
          onClick={() => void handleClear()}
        >
          {isClearing ? (
            <>
              <span className="loading loading-spinner loading-sm" />
              Clearing…
            </>
          ) : (
            "Clear lab data"
          )}
        </button>
      </div>
      {errorMessage ? (
        <div role="alert" className="alert alert-warning">
          <span>{errorMessage}</span>
        </div>
      ) : null}
      {successMessage ? (
        <div role="status" className="alert alert-success">
          <span>{successMessage}</span>
        </div>
      ) : null}
    </SectionBlock>
  );
}
