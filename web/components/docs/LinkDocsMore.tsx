import Link from "next/link";
import { docsHomeHref } from "@/lib/docs-links";

type LinkDocsMoreProps = {
  href?: string;
  children?: React.ReactNode;
  className?: string;
};

/** Compact in-app Docs deep link (same tab). */
export function LinkDocsMore({
  href = docsHomeHref(),
  children = "Learn more in Docs",
  className = "link link-primary text-sm",
}: LinkDocsMoreProps) {
  return (
    <Link href={href} className={className}>
      {children}
    </Link>
  );
}
