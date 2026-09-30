"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { NAV_LINKS } from "@/lib/nav";

/** Legacy horizontal links — prefer NavRail / NavDrawer. */
export function NavBarLinks() {
  const pathname = usePathname();

  return (
    <ul className="menu menu-horizontal px-1">
      {NAV_LINKS.map((link) => (
        <li key={link.href}>
          <Link
            href={link.href}
            className={link.isActive(pathname) ? "active" : undefined}
          >
            {link.label}
          </Link>
        </li>
      ))}
    </ul>
  );
}
