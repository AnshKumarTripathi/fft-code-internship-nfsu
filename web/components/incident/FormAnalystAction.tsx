"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { createAnalystAction } from "@/lib/api";
import type { AnalystActionCreate } from "@/lib/types";

type FormAnalystActionProps = {
  incidentId: string;
  anomalyId?: string | null;
  defaultOperatorLabel: string;
  mode: "anomaly" | "incident";
  defaultAction?: AnalystActionCreate["action"];
};

export function FormAnalystAction({
  incidentId,
  anomalyId,
  defaultOperatorLabel,
  mode,
  defaultAction,
}: FormAnalystActionProps) {
  const router = useRouter();
  const [action, setAction] = useState<AnalystActionCreate["action"]>(
    defaultAction ?? (mode === "anomaly" ? "dismiss" : "note"),
  );
  const [note, setNote] = useState("");
  const [operatorLabel, setOperatorLabel] = useState(defaultOperatorLabel);
  const [isSaving, setIsSaving] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setIsSaving(true);
    setErrorMessage("");
    const result = await createAnalystAction({
      incident_id: incidentId,
      anomaly_id: mode === "anomaly" ? anomalyId : null,
      action,
      note: note.trim() || null,
      operator_label: operatorLabel.trim() || defaultOperatorLabel,
    });
    setIsSaving(false);
    if (!result.ok) {
      setErrorMessage(result.message);
      return;
    }
    setNote("");
    router.refresh();
  }

  return (
    <form className="mt-3 flex flex-col gap-2" onSubmit={onSubmit}>
      <div className="flex flex-wrap items-end gap-2">
        <label className="form-control w-36">
          <span className="label-text mb-1">Action</span>
          <select
            className="select select-bordered select-sm"
            value={action}
            onChange={(event) =>
              setAction(event.target.value as AnalystActionCreate["action"])
            }
            suppressHydrationWarning
          >
            {mode === "anomaly" ? (
              <>
                <option value="dismiss">dismiss</option>
                <option value="note">note</option>
                <option value="reopen">reopen</option>
              </>
            ) : (
              <option value="note">note</option>
            )}
          </select>
        </label>
        <label className="form-control w-36">
          <span className="label-text mb-1">Operator</span>
          <input
            className="input input-bordered input-sm font-mono"
            value={operatorLabel}
            onChange={(event) => setOperatorLabel(event.target.value)}
            maxLength={64}
            required
            suppressHydrationWarning
          />
        </label>
        <label className="form-control min-w-48 flex-1">
          <span className="label-text mb-1">Note</span>
          <input
            className="input input-bordered input-sm"
            value={note}
            onChange={(event) => setNote(event.target.value)}
            maxLength={4000}
            placeholder={action === "note" ? "required" : "optional"}
            required={action === "note"}
            suppressHydrationWarning
          />
        </label>
        <button
          className="btn btn-sm btn-primary"
          type="submit"
          disabled={isSaving}
          suppressHydrationWarning
        >
          {isSaving ? "Saving…" : "Log action"}
        </button>
      </div>
      {errorMessage ? (
        <p role="alert" className="text-sm text-error">
          {errorMessage}
        </p>
      ) : (
        <p className="text-xs opacity-70">
          Append-only warehouse row. Undo is reopen, not delete.
        </p>
      )}
    </form>
  );
}
