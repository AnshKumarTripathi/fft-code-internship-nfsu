"use client";

import { SectionBlock } from "@/components/layout/SectionBlock";
import { LinkDocsMore } from "@/components/docs/LinkDocsMore";
import {
  docsConfigKnobsHref,
  docsLargeCorpusHref,
  docsSingleWriterHref,
} from "@/lib/docs-links";
import { formatBytes } from "@/lib/format";
import type {
  PipelineCorpusListResponse,
  PipelineShardingSettings,
  PipelineUploadFileItem,
} from "@/lib/types";

type PanelLargeCorpusProps = {
  enabled: boolean;
  settings: PipelineShardingSettings | null;
  largeCorpusMode: boolean;
  onLargeCorpusModeChange: (value: boolean) => void;
  inputPath: string;
  onInputPathChange: (value: string) => void;
  useStagedUploads: boolean;
  onUseStagedUploadsChange: (value: boolean) => void;
  corpus: PipelineCorpusListResponse | null;
  stagedFiles: PipelineUploadFileItem[];
  disabled: boolean;
  onRefreshCorpus: () => void;
};

export function PanelLargeCorpus({
  enabled,
  settings,
  largeCorpusMode,
  onLargeCorpusModeChange,
  inputPath,
  onInputPathChange,
  useStagedUploads,
  onUseStagedUploadsChange,
  corpus,
  stagedFiles,
  disabled,
  onRefreshCorpus,
}: PanelLargeCorpusProps) {
  if (!enabled || !settings) {
    return null;
  }

  return (
    <SectionBlock
      title="Large corpus (sharded)"
      description="Point at a file already on the lab host; the pipeline will split and process in parts. Multipart upload stays at 50 MiB."
    >
      <label className="label cursor-pointer justify-start gap-3 py-0">
        <input
          type="checkbox"
          className="toggle toggle-sm"
          checked={largeCorpusMode}
          disabled={disabled}
          onChange={(event) => onLargeCorpusModeChange(event.target.checked)}
        />
        <span className="label-text text-sm">
          Use sharded run (server path or one staged file)
        </span>
      </label>

      {!largeCorpusMode ? (
        <p className="text-sm text-base-content/70">
          Leave off for normal small-corpus uploads. Soft target{" "}
          {settings.target_shard_bytes
            ? formatBytes(settings.target_shard_bytes)
            : "bytes"}{" "}
          per shard; max {settings.max_shards} shards.{" "}
          <LinkDocsMore href={docsLargeCorpusHref()}>Large corpus guide</LinkDocsMore>
          {" · "}
          <LinkDocsMore href={docsConfigKnobsHref()}>Config knobs</LinkDocsMore>
        </p>
      ) : (
        <div className="flex flex-col gap-4">
          <p className="text-sm text-base-content/70">
            Prefer a path under{" "}
            <code className="fft-mono-meta">{settings.raw_log_dir}</code>. Cancel
            stops before the next shard; the current shard may finish.{" "}
            <LinkDocsMore href={docsLargeCorpusHref()}>
              Path A / Path B how-to
            </LinkDocsMore>{" "}
            ·{" "}
            <LinkDocsMore href={docsSingleWriterHref()}>
              Single-writer rules
            </LinkDocsMore>{" "}
            still apply.
          </p>

          <label className="label cursor-pointer justify-start gap-3 py-0">
            <input
              type="checkbox"
              className="checkbox checkbox-sm"
              checked={useStagedUploads}
              disabled={disabled}
              onChange={(event) => {
                onUseStagedUploadsChange(event.target.checked);
                if (event.target.checked) {
                  onInputPathChange("");
                }
              }}
            />
            <span className="label-text text-sm">
              Use the single staged upload (
              {stagedFiles.length === 1
                ? stagedFiles[0].name
                : `${stagedFiles.length} staged — need exactly one`}
              )
            </span>
          </label>

          {!useStagedUploads ? (
            <label className="form-control w-full max-w-2xl">
              <span className="label-text text-sm">Server path</span>
              <input
                type="text"
                className="input input-bordered input-sm w-full font-mono text-xs"
                value={inputPath}
                disabled={disabled}
                placeholder={`${settings.raw_log_dir.replace(/[\\/]$/, "")}/huge.log`}
                onChange={(event) => onInputPathChange(event.target.value)}
              />
            </label>
          ) : null}

          <div className="flex flex-col gap-2">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-medium">Existing raw (top-level)</span>
              <button
                type="button"
                className="btn btn-ghost btn-xs"
                disabled={disabled}
                onClick={onRefreshCorpus}
              >
                Refresh
              </button>
            </div>
            {corpus && corpus.files.length > 0 ? (
              <ul className="max-h-40 overflow-y-auto text-sm">
                {corpus.files.map((file) => {
                  const candidate = `${corpus.raw_log_dir.replace(/[\\/]$/, "")}/${file.name}`;
                  return (
                    <li key={file.sha256 + file.name}>
                      <button
                        type="button"
                        className="btn btn-ghost btn-xs justify-start font-mono"
                        disabled={disabled || useStagedUploads}
                        onClick={() => {
                          onUseStagedUploadsChange(false);
                          onInputPathChange(candidate);
                        }}
                      >
                        {file.name} ({formatBytes(file.size_bytes)})
                      </button>
                    </li>
                  );
                })}
              </ul>
            ) : (
              <p className="text-sm text-base-content/70">
                No top-level files listed under raw (uploads live in a subfolder).
              </p>
            )}
          </div>
        </div>
      )}
    </SectionBlock>
  );
}
