"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useId, useState } from "react";
import { NAV_LINKS } from "@/lib/nav";

export function NavDrawer() {
  const pathname = usePathname();
  const drawerId = useId();
  const [open, setOpen] = useState(false);

  return (
    <div className="drawer w-auto">
      <input
        id={drawerId}
        type="checkbox"
        className="drawer-toggle"
        checked={open}
        onChange={(event) => setOpen(event.target.checked)}
      />
      <div className="drawer-content">
        <label
          htmlFor={drawerId}
          className="btn btn-ghost btn-square btn-sm"
          aria-label="Open navigation"
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            className="h-5 w-5"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            aria-hidden
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M4 6h16M4 12h16M4 18h16"
            />
          </svg>
        </label>
      </div>
      <div className="drawer-side z-40">
        <label
          htmlFor={drawerId}
          aria-label="Close navigation"
          className="drawer-overlay"
        />
        <nav className="flex min-h-full w-64 flex-col bg-base-100 p-4">
          <p className="mb-4 text-lg font-semibold tracking-tight">Log Anomaly</p>
          <ul className="menu w-full gap-0.5 p-0">
            {NAV_LINKS.map((link) => (
              <li key={link.href}>
                <Link
                  href={link.href}
                  className={link.isActive(pathname) ? "active" : undefined}
                  onClick={() => setOpen(false)}
                >
                  {link.label}
                </Link>
              </li>
            ))}
          </ul>
        </nav>
      </div>
    </div>
  );
}
