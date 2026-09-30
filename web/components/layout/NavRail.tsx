"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { NAV_LINKS } from "@/lib/nav";

export function NavRail() {
  const pathname = usePathname();

  return (
    <aside className="sticky top-0 hidden h-screen w-56 shrink-0 flex-col border-r border-base-300 bg-base-200 md:flex">
      <div className="border-b border-base-300 px-4 py-4">
        <Link
          href="/"
          className="block text-lg font-semibold tracking-tight text-base-content transition-colors hover:text-primary"
        >
          Log Anomaly
        </Link>
        <p className="mt-1 text-xs text-base-content/60">Lab console</p>
      </div>
      <nav className="flex flex-1 flex-col gap-0.5 p-2" aria-label="Primary">
        {NAV_LINKS.map((link) => {
          const active = link.isActive(pathname);
          return (
            <Link
              key={link.href}
              href={link.href}
              className={`rounded-lg px-3 py-2 text-sm transition-colors ${
                active
                  ? "border border-primary bg-primary/10 font-medium text-primary"
                  : "border border-transparent text-base-content/80 hover:bg-base-100"
              }`}
            >
              {link.label}
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}
