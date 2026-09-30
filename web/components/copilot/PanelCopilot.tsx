"use client";

import { useCallback, useEffect, useId, useRef, useState, type PointerEvent as ReactPointerEvent } from "react";
import { usePathname } from "next/navigation";
import {
  fetchCopilotStatus,
  postCopilotChat,
} from "@/lib/api";
import type { CopilotStatus } from "@/lib/types";
import {
  clampCopilotPanelSize,
  entityIdFromPath,
  incidentIdFromPath,
  isEntitiesRoute,
  loadCopilotPanelSize,
  reportFilenameFromPath,
  saveCopilotPanelSize,
  type CopilotPanelSize,
} from "@/lib/copilot";
import {
  useCopilot,
  type CopilotAttachmentChip,
} from "@/components/copilot/ProviderCopilot";

type ResizeEdge = "left" | "top" | "top-left";

function chipLabel(chip: CopilotAttachmentChip): string {
  const label = (chip.label || chip.kind || "attachment").trim();
  return label.length > 40 ? `${label.slice(0, 37)}…` : label;
}

export function PanelCopilot() {
  const pathname = usePathname();
  const titleId = useId();
  const panelRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLTextAreaElement | null>(null);
  const resizeRef = useRef<{
    edge: ResizeEdge;
    startX: number;
    startY: number;
    startWidth: number;
    startHeight: number;
  } | null>(null);
  const {
    isOpen,
    openPanel,
    closePanel,
    togglePanel,
    attachments,
    removeAttachment,
    clearAttachments,
    messages,
    setMessages,
  } = useCopilot();

  const [status, setStatus] = useState<CopilotStatus | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  const [isSending, setIsSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [panelSize, setPanelSize] = useState<CopilotPanelSize>(() =>
    loadCopilotPanelSize(),
  );

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const result = await fetchCopilotStatus();
      if (cancelled) {
        return;
      }
      if (!result.ok) {
        setStatus(null);
        setStatusError(result.message);
        return;
      }
      setStatus(result.data);
      setStatusError(null);
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    function onResize() {
      setPanelSize((prev) => clampCopilotPanelSize(prev));
    }
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  useEffect(() => {
    if (!isOpen) {
      return;
    }
    const node = inputRef.current;
    node?.focus();

    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        closePanel();
        return;
      }
      if (event.key !== "Tab" || !panelRef.current) {
        return;
      }
      const focusable = panelRef.current.querySelectorAll<HTMLElement>(
        'button:not([disabled]), textarea:not([disabled]), [href], [tabindex]:not([tabindex="-1"])',
      );
      if (focusable.length === 0) {
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const active = document.activeElement as HTMLElement | null;
      if (event.shiftKey && active === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && active === last) {
        event.preventDefault();
        first.focus();
      }
    }

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [isOpen, closePanel]);

  const onResizePointerMove = useCallback((event: PointerEvent) => {
    const active = resizeRef.current;
    if (!active) {
      return;
    }
    const deltaX = event.clientX - active.startX;
    const deltaY = event.clientY - active.startY;
    // Panel is anchored bottom-right: drag left edge left → wider; drag top up → taller.
    let nextWidth = active.startWidth;
    let nextHeight = active.startHeight;
    if (active.edge === "left" || active.edge === "top-left") {
      nextWidth = active.startWidth - deltaX;
    }
    if (active.edge === "top" || active.edge === "top-left") {
      nextHeight = active.startHeight - deltaY;
    }
    const next = clampCopilotPanelSize({ width: nextWidth, height: nextHeight });
    setPanelSize(next);
  }, []);

  const onResizePointerUp = useCallback(() => {
    if (!resizeRef.current) {
      return;
    }
    resizeRef.current = null;
    setPanelSize((prev) => {
      const next = clampCopilotPanelSize(prev);
      saveCopilotPanelSize(next);
      return next;
    });
    window.removeEventListener("pointermove", onResizePointerMove);
    window.removeEventListener("pointerup", onResizePointerUp);
    window.removeEventListener("pointercancel", onResizePointerUp);
  }, [onResizePointerMove]);

  function startResize(edge: ResizeEdge, event: ReactPointerEvent) {
    event.preventDefault();
    event.stopPropagation();
    resizeRef.current = {
      edge,
      startX: event.clientX,
      startY: event.clientY,
      startWidth: panelSize.width,
      startHeight: panelSize.height,
    };
    window.addEventListener("pointermove", onResizePointerMove);
    window.addEventListener("pointerup", onResizePointerUp);
    window.addEventListener("pointercancel", onResizePointerUp);
  }

  useEffect(() => {
    return () => {
      window.removeEventListener("pointermove", onResizePointerMove);
      window.removeEventListener("pointerup", onResizePointerUp);
      window.removeEventListener("pointercancel", onResizePointerUp);
    };
  }, [onResizePointerMove, onResizePointerUp]);

  const enabled = Boolean(status?.enabled);
  const fabTitle = statusError
    ? statusError
    : enabled
      ? "Open assistive copilot"
      : "Copilot disabled — set COPILOT_ENABLED and copilot.enabled (dual-gate)";

  async function onSend() {
    const content = draft.trim();
    if (!content || isSending) {
      return;
    }
    if (!enabled) {
      setError(
        statusError ??
          "Copilot is disabled. Enable dual-gate (env + YAML) and retry.",
      );
      return;
    }

    const nextMessages = [...messages, { role: "user", content }];
    setMessages(nextMessages);
    setDraft("");
    setIsSending(true);
    setError(null);

    const reportFilename = reportFilenameFromPath(pathname);
    const pathIncidentId = incidentIdFromPath(pathname);
    const pathEntityId = entityIdFromPath(pathname);
    const incidentId =
      attachments.find((item) => item.incident_id)?.incident_id ??
      pathIncidentId;

    const pathAttachments: Array<{
      kind: string;
      route: string;
      incident_id?: string | null;
      entity_id?: string | null;
      label: string;
      text: string;
    }> = [];

    if (
      reportFilename &&
      !attachments.some((item) =>
        (item.route || "").includes(`/reports/${reportFilename}`),
      )
    ) {
      pathAttachments.push({
        kind: "page_context",
        route: `/reports/${reportFilename}`,
        incident_id: pathIncidentId,
        label: `Report: ${reportFilename}`,
        text: `Viewing report ${reportFilename}`,
      });
    }

    if (
      isEntitiesRoute(pathname) &&
      !attachments.some((item) => (item.route || "").startsWith("/entities"))
    ) {
      pathAttachments.push({
        kind: "page_context",
        route: pathEntityId ? `/entities/${pathEntityId}` : "/entities",
        entity_id: pathEntityId,
        label: pathEntityId ? `Entity: ${pathEntityId}` : "Entities registry",
        text: pathEntityId
          ? `Viewing entity ${pathEntityId}`
          : "Viewing Entities registry",
      });
    }

    const result = await postCopilotChat({
      messages: nextMessages,
      attachments: [
        ...attachments.map(({ id: _id, ...rest }) => rest),
        ...pathAttachments,
      ],
      incident_id: incidentId,
    });

    setIsSending(false);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    setMessages((prev) => [
      ...prev,
      { role: "assistant", content: result.data.reply },
    ]);
    clearAttachments();
  }

  return (
    <>
      <button
        type="button"
        className="btn btn-circle btn-primary fixed bottom-5 right-5 z-40 shadow-md"
        aria-label={fabTitle}
        title={fabTitle}
        aria-expanded={isOpen}
        aria-controls={isOpen ? titleId : undefined}
        disabled={Boolean(statusError) && !status}
        onClick={() => {
          if (!enabled) {
            openPanel();
            setError(
              statusError ??
                "Copilot is disabled. Set COPILOT_ENABLED=true in code/.env and copilot.enabled: true in pipeline.yaml.",
            );
            return;
          }
          togglePanel();
        }}
      >
        <span className="text-lg font-semibold" aria-hidden>
          ?
        </span>
      </button>

      {isOpen ? (
        <div
          ref={panelRef}
          role="dialog"
          aria-modal="true"
          aria-labelledby={titleId}
          className="fft-paper-panel fft-float-panel fixed bottom-20 right-5 z-40 flex flex-col overflow-hidden"
          style={{ width: panelSize.width, height: panelSize.height }}
          data-copilot-panel
        >
          <div
            className="absolute left-0 top-0 z-10 h-3 w-3 cursor-nw-resize"
            aria-hidden
            onPointerDown={(event) => startResize("top-left", event)}
            title="Resize"
          />
          <div
            className="absolute left-0 top-3 z-10 h-[calc(100%-0.75rem)] w-1.5 cursor-ew-resize hover:bg-primary/20"
            aria-hidden
            onPointerDown={(event) => startResize("left", event)}
            title="Resize width"
          />
          <div
            className="absolute left-3 top-0 z-10 h-1.5 w-[calc(100%-0.75rem)] cursor-ns-resize hover:bg-primary/20"
            aria-hidden
            onPointerDown={(event) => startResize("top", event)}
            title="Resize height"
          />

          <header className="flex shrink-0 items-start justify-between gap-2 border-b border-base-300 px-3 py-2">
            <div className="min-w-0">
              <h2 id={titleId} className="text-sm font-semibold">
                Assistive copilot
              </h2>
              <p className="mt-0.5 text-xs text-base-content/70">
                Assistive only — verify against Why flagged and the deterministic
                report. Drag the top or left edge to resize.
              </p>
              {status ? (
                <p className="fft-mono-meta mt-1">
                  {status.enabled ? "on" : "off"} · {status.provider}
                  {status.model ? ` · ${status.model}` : ""}
                </p>
              ) : null}
            </div>
            <button
              type="button"
              className="btn btn-ghost btn-xs"
              onClick={closePanel}
            >
              Close
            </button>
          </header>

          <div className="min-h-0 flex-1 space-y-2 overflow-y-auto px-3 py-2">
            {messages.length === 0 ? (
              <p className="text-sm text-base-content/70">
                Ask about an incident, report, or Docs. Use{" "}
                <span className="font-medium">Add to chat</span> on Why flagged
                or Docs to attach page context.
              </p>
            ) : null}
            {messages.map((message, index) => (
              <div
                key={`${message.role}-${index}`}
                className={
                  message.role === "user"
                    ? "rounded-box bg-primary/10 px-2 py-1.5 text-sm"
                    : "rounded-box bg-base-200 px-2 py-1.5 text-sm"
                }
              >
                <p className="text-[0.65rem] uppercase tracking-wide text-base-content/60">
                  {message.role === "user" ? "You" : "Copilot"}
                </p>
                <p className="mt-0.5 whitespace-pre-wrap">{message.content}</p>
              </div>
            ))}
            {isSending ? (
              <p className="text-xs text-base-content/60" role="status">
                Thinking…
              </p>
            ) : null}
          </div>

          {attachments.length > 0 ? (
            <div className="flex shrink-0 flex-wrap gap-1 border-t border-base-300 px-3 py-2">
              {attachments.map((chip) => (
                <span
                  key={chip.id}
                  className="badge badge-outline gap-1 max-w-full"
                  title={chip.text ?? chip.label ?? ""}
                >
                  <span className="truncate">{chipLabel(chip)}</span>
                  <button
                    type="button"
                    className="btn btn-ghost btn-xs h-4 min-h-0 px-1"
                    aria-label={`Remove ${chipLabel(chip)}`}
                    onClick={() => removeAttachment(chip.id)}
                  >
                    ×
                  </button>
                </span>
              ))}
            </div>
          ) : null}

          {error ? (
            <p className="shrink-0 border-t border-base-300 px-3 py-2 text-xs text-error" role="alert">
              {error}
            </p>
          ) : null}

          <form
            className="flex shrink-0 flex-col gap-2 border-t border-base-300 p-3"
            onSubmit={(event) => {
              event.preventDefault();
              void onSend();
            }}
          >
            <label className="sr-only" htmlFor={`${titleId}-input`}>
              Message
            </label>
            <textarea
              id={`${titleId}-input`}
              ref={inputRef}
              className="textarea textarea-bordered textarea-sm min-h-16 w-full"
              rows={2}
              value={draft}
              disabled={isSending}
              placeholder={
                enabled
                  ? "Ask in plain language…"
                  : "Copilot disabled — dual-gate off"
              }
              onChange={(event) => setDraft(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && !event.shiftKey) {
                  event.preventDefault();
                  void onSend();
                }
              }}
            />
            <button
              type="submit"
              className="btn btn-primary btn-sm"
              disabled={isSending || !draft.trim()}
            >
              Send
            </button>
          </form>
        </div>
      ) : null}
    </>
  );
}
