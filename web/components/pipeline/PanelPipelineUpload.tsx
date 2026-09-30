"use client";

import { useRef, type ChangeEvent, type DragEvent } from "react";
import { formatBytes, formatUtc, snippet } from "@/lib/format";
import type { PipelineUploadFileItem } from "@/lib/types";

type PanelPipelineUploadProps = {
  files: PipelineUploadFileItem[];
  uploadDir: string | null;
  disabled: boolean;
  isUploading: boolean;
  isSeeding: boolean;
  errorMessage: string;
  onUpload: (files: File[]) => void;
  onDelete: (name: string) => void;
  onSeedDemo: () => void;
  onRefresh: () => void;
};

export function PanelPipelineUpload({
  files,
  uploadDir,
  disabled,
  isUploading,
  isSeeding,
  errorMessage,
  onUpload,
  onDelete,
  onSeedDemo,
  onRefresh,
}: PanelPipelineUploadProps) {
  const inputRef = useRef<HTMLInputElement>(null);

  function takeFiles(list: FileList | null) {
    if (!list || list.length === 0 || disabled) {
      return;
    }
    onUpload(Array.from(list));
    if (inputRef.current) {
      inputRef.current.value = "";
    }
  }

  function onInputChange(event: ChangeEvent<HTMLInputElement>) {
    takeFiles(event.target.files);
  }

  function onDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    if (disabled) {
      return;
    }
    takeFiles(event.dataTransfer.files);
  }

  return (
    <section className="flex flex-col gap-3">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold">Staged logs</h2>
          <p className="text-sm opacity-70">
            Files land under{" "}
            <code>{uploadDir ?? "pipeline_ui.upload_dir"}</code> (inside raw).
            Upload does not start a run.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            className="btn btn-sm btn-ghost"
            onClick={onRefresh}
            disabled={disabled || isUploading || isSeeding}
          >
            Refresh
          </button>
          <button
            type="button"
            className="btn btn-sm"
            onClick={onSeedDemo}
            disabled={disabled || isUploading || isSeeding}
            aria-busy={isSeeding}
          >
            {isSeeding ? "Seeding…" : "Load demo corpus"}
          </button>
          <button
            type="button"
            className="btn btn-sm btn-primary"
            disabled={disabled || isUploading || isSeeding}
            onClick={() => inputRef.current?.click()}
            aria-busy={isUploading}
          >
            {isUploading ? "Uploading…" : "Choose files"}
          </button>
          <input
            ref={inputRef}
            type="file"
            className="hidden"
            multiple
            accept=".log,.txt,.json,.jsonl,.csv,text/plain,application/json"
            disabled={disabled || isUploading || isSeeding}
            onChange={onInputChange}
          />
        </div>
      </div>

      {disabled ? (
        <div role="status" className="alert alert-info">
          <span>Uploads are paused while a pipeline job is running.</span>
        </div>
      ) : null}

      {errorMessage ? (
        <div role="alert" className="alert alert-error">
          <span>{errorMessage}</span>
        </div>
      ) : null}

      <div
        className="rounded-box border border-base-300 border-dashed px-4 py-8 text-center"
        onDragOver={(event) => event.preventDefault()}
        onDrop={onDrop}
      >
        <p className="text-sm opacity-70">
          Drop <code>.log</code> / <code>.txt</code> / <code>.json</code> /{" "}
          <code>.jsonl</code> / <code>.csv</code> here, or use Choose files.
        </p>
      </div>

      {files.length === 0 ? (
        <div role="status" className="alert">
          <span>
            No staged files yet. Upload logs or load the demo corpus before
            starting a run.
          </span>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="table table-sm">
            <thead>
              <tr>
                <th>Name</th>
                <th>Size</th>
                <th>SHA-256</th>
                <th>Modified (UTC)</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {files.map((file) => (
                <tr key={file.name}>
                  <td className="font-mono text-sm">{file.name}</td>
                  <td>{formatBytes(file.size_bytes)}</td>
                  <td className="font-mono text-xs" title={file.sha256}>
                    {snippet(file.sha256, 12)}
                  </td>
                  <td className="font-mono text-sm">
                    {formatUtc(file.modified_at)}
                  </td>
                  <td className="text-right">
                    <button
                      type="button"
                      className="btn btn-ghost btn-xs"
                      disabled={disabled || isUploading || isSeeding}
                      onClick={() => onDelete(file.name)}
                    >
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
