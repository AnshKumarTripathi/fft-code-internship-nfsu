"use client";

import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";

type InvestigationTab = "overview" | "analysis" | "events";

const TABS: { key: InvestigationTab; label: string; suffix: string }[] = [
  { key: "overview", label: "Overview", suffix: "" },
  { key: "analysis", label: "Analysis", suffix: "/analysis" },
  { key: "events", label: "Events", suffix: "/events" },
];

const WINDOW_KEYS = ["start", "end", "pad_hours"] as const;

type NavInvestigationTabsProps = {
  basePath: string;
};

export function NavInvestigationTabs({ basePath }: NavInvestigationTabsProps) {
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const eventsPath = `${basePath}/events`;
  const onEvents = pathname === eventsPath;

  function hrefFor(suffix: string, tab: InvestigationTab): string {
    const params = new URLSearchParams();
    for (const key of WINDOW_KEYS) {
      const value = searchParams.get(key);
      if (value) {
        params.set(key, value);
      }
    }
    if (tab === "events") {
      const step = searchParams.get("step");
      if (step) {
        params.set("step", step);
      }
      if (onEvents) {
        const page = searchParams.get("page");
        if (page && page !== "1") {
          params.set("page", page);
        }
      }
    }
    const qs = params.toString();
    const path = `${basePath}${suffix}`;
    return qs ? `${path}?${qs}` : path;
  }

  function isActive(tab: InvestigationTab, suffix: string): boolean {
    if (tab === "overview") {
      return pathname === basePath;
    }
    return pathname === `${basePath}${suffix}`;
  }

  return (
    <div
      className="tabs tabs-border border-b border-base-300"
      role="tablist"
      aria-label="Investigation"
    >
      {TABS.map((tab) => (
        <Link
          key={tab.key}
          role="tab"
          href={hrefFor(tab.suffix, tab.key)}
          className={isActive(tab.key, tab.suffix) ? "tab tab-active" : "tab"}
          aria-selected={isActive(tab.key, tab.suffix)}
        >
          {tab.label}
        </Link>
      ))}
    </div>
  );
}
