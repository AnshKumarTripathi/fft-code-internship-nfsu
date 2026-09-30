import Link from "next/link";
import { adjacentDocs } from "@/lib/docs-tree";

type NavDocsPrevNextProps = {
  slug: string;
};

export function NavDocsPrevNext({ slug }: NavDocsPrevNextProps) {
  const { prev, next } = adjacentDocs(slug);

  return (
    <nav
      className="mt-10 flex flex-wrap items-stretch justify-between gap-3 border-t border-base-300 pt-6"
      aria-label="Adjacent chapters"
    >
      {prev ? (
        <Link
          href={prev.href}
          className="fft-paper-panel max-w-xs flex-1 px-4 py-3 transition-colors hover:border-primary/40"
        >
          <p className="text-xs uppercase tracking-wide text-base-content/50">
            Previous
          </p>
          <p className="mt-1 text-sm font-medium">{prev.title}</p>
        </Link>
      ) : (
        <Link
          href="/docs"
          className="fft-paper-panel max-w-xs flex-1 px-4 py-3 transition-colors hover:border-primary/40"
        >
          <p className="text-xs uppercase tracking-wide text-base-content/50">
            Previous
          </p>
          <p className="mt-1 text-sm font-medium">Docs home</p>
        </Link>
      )}

      {next ? (
        <Link
          href={next.href}
          className="fft-paper-panel max-w-xs flex-1 px-4 py-3 text-right transition-colors hover:border-primary/40"
        >
          <p className="text-xs uppercase tracking-wide text-base-content/50">
            Next
          </p>
          <p className="mt-1 text-sm font-medium">{next.title}</p>
        </Link>
      ) : (
        <span className="max-w-xs flex-1" />
      )}
    </nav>
  );
}
