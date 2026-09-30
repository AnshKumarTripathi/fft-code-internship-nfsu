"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { incidentListHref, pipelineHref } from "@/lib/hrefs";

const STORAGE_KEY = "fft.guidedSteps.dismissed";

const STEPS = [
  "Name an analysis on Pipeline",
  "Upload or seed log files",
  "Start run and wait for correlate",
  "Open triage on the analysis card",
  "Read Why flagged on an incident",
] as const;

/** Phase 67 — optional dismissible first-run coach marks. */
export function BannerGuidedSteps() {
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    const id = window.setTimeout(() => {
      try {
        if (window.localStorage.getItem(STORAGE_KEY) === "1") {
          return;
        }
      } catch {
        // localStorage may be blocked; still show once per session.
      }
      setIsVisible(true);
    }, 0);
    return () => window.clearTimeout(id);
  }, []);

  function dismiss() {
    try {
      window.localStorage.setItem(STORAGE_KEY, "1");
    } catch {
      // ignore
    }
    setIsVisible(false);
  }

  if (!isVisible) {
    return null;
  }

  return (
    <div role="status" className="alert alert-info">
      <div className="flex w-full flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex flex-col gap-2">
          <p className="font-medium">First-run path</p>
          <ol className="list-decimal space-y-1 pl-5 text-sm">
            {STEPS.map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ol>
          <p className="text-sm text-base-content/80">
            Start on{" "}
            <Link className="link" href={pipelineHref()}>
              Pipeline
            </Link>
            ; after a run, open triage or the live{" "}
            <Link className="link" href={incidentListHref({ disposition: "open" })}>
              Incidents
            </Link>{" "}
            queue.
          </p>
        </div>
        <button type="button" className="btn btn-sm" onClick={dismiss}>
          Dismiss
        </button>
      </div>
    </div>
  );
}
