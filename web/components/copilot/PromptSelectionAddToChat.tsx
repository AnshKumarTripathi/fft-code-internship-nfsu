"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { usePathname } from "next/navigation";
import { useCopilot } from "@/components/copilot/ProviderCopilot";
import { MAX_ATTACHMENT_CHARS, incidentIdFromPath } from "@/lib/copilot";

const MIN_SELECTION_CHARS = 4;
const PROMPT_GAP_PX = 8;

type SelectionPrompt = {
  text: string;
  top: number;
  left: number;
  placeAbove: boolean;
};

function docsSlugFromPath(pathname: string): string | null {
  if (!pathname.startsWith("/docs/")) {
    return null;
  }
  const slug = pathname.slice("/docs/".length).replace(/\/$/, "");
  return slug || null;
}

function labelForPath(pathname: string): string {
  if (pathname.startsWith("/docs")) {
    return "Selection: Docs";
  }
  if (pathname.startsWith("/reports")) {
    return "Selection: Report";
  }
  if (pathname.startsWith("/incidents")) {
    return "Selection: Incident";
  }
  return "Page selection";
}

function isExcludedTarget(node: Node | null): boolean {
  if (!node) {
    return true;
  }
  const element =
    node.nodeType === Node.ELEMENT_NODE
      ? (node as Element)
      : node.parentElement;
  if (!element) {
    return true;
  }
  if (element.closest("[data-copilot-panel], [data-copilot-selection-prompt]")) {
    return true;
  }
  if (element.closest("input, textarea, select, [contenteditable='true']")) {
    return true;
  }
  return false;
}

function readSelectionPrompt(): SelectionPrompt | null {
  const selection = window.getSelection();
  if (!selection || selection.isCollapsed || selection.rangeCount === 0) {
    return null;
  }
  const text = selection.toString().replace(/\s+/g, " ").trim();
  if (text.length < MIN_SELECTION_CHARS) {
    return null;
  }
  const range = selection.getRangeAt(0);
  if (
    isExcludedTarget(range.commonAncestorContainer) ||
    isExcludedTarget(selection.anchorNode) ||
    isExcludedTarget(selection.focusNode)
  ) {
    return null;
  }
  const rect = range.getBoundingClientRect();
  if (rect.width === 0 && rect.height === 0) {
    return null;
  }
  const capped =
    text.length > MAX_ATTACHMENT_CHARS
      ? text.slice(0, MAX_ATTACHMENT_CHARS)
      : text;
  const placeAbove = rect.top >= 56;
  const top = placeAbove
    ? Math.max(8, rect.top - PROMPT_GAP_PX)
    : Math.min(window.innerHeight - 8, rect.bottom + PROMPT_GAP_PX);
  const left = Math.min(
    window.innerWidth - 16,
    Math.max(16, rect.left + rect.width / 2),
  );
  return { text: capped, top, left, placeAbove };
}

export function PromptSelectionAddToChat() {
  const pathname = usePathname();
  const { addAttachment } = useCopilot();
  const [prompt, setPrompt] = useState<SelectionPrompt | null>(null);
  const promptRef = useRef<HTMLDivElement | null>(null);

  const clearPrompt = useCallback(() => setPrompt(null), []);

  const refreshPrompt = useCallback(() => {
    setPrompt(readSelectionPrompt());
  }, []);

  useEffect(() => {
    function onMouseUp() {
      // Let the browser finish updating the selection before reading it.
      window.setTimeout(() => {
        refreshPrompt();
      }, 0);
    }

    function onKeyUp(event: KeyboardEvent) {
      if (event.key === "Shift" || event.key.startsWith("Arrow")) {
        refreshPrompt();
      }
    }

    function onScroll() {
      clearPrompt();
    }

    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        clearPrompt();
      }
    }

    function onPointerDown(event: PointerEvent) {
      const target = event.target as Node | null;
      if (promptRef.current && target && promptRef.current.contains(target)) {
        return;
      }
      // Hide when clicking elsewhere; a new selection will re-show on mouseup.
      clearPrompt();
    }

    document.addEventListener("mouseup", onMouseUp);
    document.addEventListener("keyup", onKeyUp);
    document.addEventListener("keydown", onKeyDown);
    document.addEventListener("pointerdown", onPointerDown, true);
    window.addEventListener("scroll", onScroll, true);
    return () => {
      document.removeEventListener("mouseup", onMouseUp);
      document.removeEventListener("keyup", onKeyUp);
      document.removeEventListener("keydown", onKeyDown);
      document.removeEventListener("pointerdown", onPointerDown, true);
      window.removeEventListener("scroll", onScroll, true);
    };
  }, [clearPrompt, refreshPrompt]);

  useEffect(() => {
    clearPrompt();
  }, [pathname, clearPrompt]);

  if (!prompt) {
    return null;
  }

  return (
    <div
      ref={promptRef}
      data-copilot-selection-prompt
      role="dialog"
      aria-label="Add selection to chat"
      className={`fixed z-[60] -translate-x-1/2 ${
        prompt.placeAbove ? "-translate-y-full" : ""
      }`}
      style={{ top: prompt.top, left: prompt.left }}
    >
      <div className="fft-paper-panel fft-float-panel flex max-w-xs flex-col gap-1 px-3 py-2">
        <p className="text-xs text-base-content/70">
          Add this highlight to chat?
        </p>
        <div className="flex items-center gap-2">
          <button
            type="button"
            className="btn btn-primary btn-xs"
            onClick={() => {
              addAttachment({
                kind: "page_selection",
                label: labelForPath(pathname),
                text: prompt.text,
                route: pathname,
                incident_id: incidentIdFromPath(pathname),
                slug: docsSlugFromPath(pathname),
              });
              window.getSelection()?.removeAllRanges();
              clearPrompt();
            }}
          >
            Add to chat
          </button>
          <button
            type="button"
            className="btn btn-ghost btn-xs"
            onClick={clearPrompt}
          >
            Dismiss
          </button>
        </div>
      </div>
    </div>
  );
}
