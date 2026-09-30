"use client";

import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import { formatUtc } from "@/lib/format";

export function FormEntityWindow() {
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const windowStart = searchParams.get("start") ?? "";
  const windowEnd = searchParams.get("end") ?? "";
  const padHours = searchParams.get("pad_hours") ?? "6";
  const step = searchParams.get("step");

  return (
    <div className="flex flex-col gap-3">
      {windowStart || windowEnd ? (
        <p className="text-sm opacity-70">
          Window {windowStart ? formatUtc(windowStart) : "…"} –{" "}
          {windowEnd ? formatUtc(windowEnd) : "…"}.
        </p>
      ) : null}
      <form
        className="flex flex-wrap items-end gap-3"
        method="get"
        action={pathname}
      >
        {step ? <input type="hidden" name="step" value={step} /> : null}
        <label className="form-control min-w-48 flex-1">
          <span className="label-text mb-1">Start (ISO UTC)</span>
          <input
            className="input input-bordered input-sm font-mono"
            name="start"
            defaultValue={windowStart}
            placeholder="2024-01-01T00:00:00Z"
            suppressHydrationWarning
          />
        </label>
        <label className="form-control min-w-48 flex-1">
          <span className="label-text mb-1">End (ISO UTC)</span>
          <input
            className="input input-bordered input-sm font-mono"
            name="end"
            defaultValue={windowEnd}
            placeholder="2024-01-02T00:00:00Z"
            suppressHydrationWarning
          />
        </label>
        <label className="form-control w-28">
          <span className="label-text mb-1">Pad hours</span>
          <input
            className="input input-bordered input-sm font-mono"
            name="pad_hours"
            type="number"
            min={0}
            defaultValue={padHours}
            suppressHydrationWarning
          />
        </label>
        <button
          className="btn btn-sm btn-primary"
          type="submit"
          suppressHydrationWarning
        >
          Apply window
        </button>
        <Link className="btn btn-sm btn-ghost" href={pathname}>
          Clear
        </Link>
      </form>
    </div>
  );
}
