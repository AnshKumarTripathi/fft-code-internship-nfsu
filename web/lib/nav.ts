export type NavLink = {
  href: string;
  label: string;
  isActive: (pathname: string) => boolean;
};

export const NAV_LINKS: NavLink[] = [
  {
    href: "/",
    label: "Pipeline",
    isActive: (pathname) =>
      pathname === "/" || pathname.startsWith("/pipeline"),
  },
  {
    href: "/incidents",
    label: "Triage",
    isActive: (pathname) => pathname.startsWith("/incidents"),
  },
  {
    href: "/entities",
    label: "Entities",
    isActive: (pathname) => pathname.startsWith("/entities"),
  },
  {
    href: "/reports",
    label: "Reports",
    isActive: (pathname) => pathname.startsWith("/reports"),
  },
  {
    href: "/runs",
    label: "Runs",
    isActive: (pathname) => pathname.startsWith("/runs"),
  },
  {
    href: "/docs",
    label: "Docs",
    isActive: (pathname) => pathname.startsWith("/docs"),
  },
  {
    href: "/settings",
    label: "Settings",
    isActive: (pathname) => pathname.startsWith("/settings"),
  },
];
