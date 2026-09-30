import Link from "next/link";
import { ShellDocs } from "@/components/docs/ShellDocs";
import { DOC_PART_LABELS, DOC_TREE, type DocPart } from "@/lib/docs-tree";

export const dynamic = "force-static";

export const metadata = {
  title: "Docs · Log Anomaly",
  description:
    "In-app product manual. Static pages — works when the API is down.",
};

export default function DocsHomePage() {
  const parts = Object.keys(DOC_PART_LABELS) as DocPart[];

  return (
    <ShellDocs>
      <div className="min-w-0 max-w-3xl">
        <p className="text-xs uppercase tracking-wide text-base-content/60">
          Documentation
        </p>
        <h1 className="mt-1 text-3xl font-semibold tracking-tight">
          Documentation
        </h1>
        <p className="mt-3 text-base leading-relaxed text-base-content/80">
          This is the in-app manual for the log anomaly lab: how to run a
          session, how to navigate every screen, the maths behind each detector,
          and reference tables for KPIs, playbooks, and troubleshooting.
        </p>
        <p className="mt-3 text-base leading-relaxed text-base-content/80">
          Docs stay readable even if the API is down. Short “What is this?”
          blurbs on triage screens remain available; this section is the longer
          manual. Start with{" "}
          <Link className="link" href="/docs/getting-started">
            Getting started
          </Link>
          ,{" "}
          <Link className="link" href="/docs/navigate">
            Navigate the UI
          </Link>
          , or{" "}
          <Link className="link" href="/docs/workflows">
            Workflows
          </Link>
          .
        </p>

        <div className="mt-6 flex flex-wrap gap-2">
          <Link
            className="btn btn-primary btn-sm"
            href="/docs/getting-started/quick-start"
          >
            Quick start
          </Link>
          <Link
            className="btn btn-ghost btn-sm"
            href="/docs/getting-started"
          >
            Getting started
          </Link>
          <Link className="btn btn-ghost btn-sm" href="/docs/workflows">
            Workflows
          </Link>
          <Link className="btn btn-ghost btn-sm" href="/docs/navigate">
            Navigate the UI
          </Link>
          <Link className="btn btn-ghost btn-sm" href="/docs/reference">
            Reference
          </Link>
          <Link className="btn btn-ghost btn-sm" href="/docs/maths">
            Maths
          </Link>
        </div>

        <div className="alert mt-6 text-sm" role="status">
          <span>
            Tip: from triage screens, charts, and Why flagged you can open the
            matching Docs chapter for more detail. For API contracts, use the
            API docs on port <code className="font-mono text-xs">8000</code>.
          </span>
        </div>

        <section className="mt-10 space-y-8" aria-label="Catalogue">
          {parts.map((part) => {
            const hubs = DOC_TREE.filter((node) => node.part === part);
            return (
              <div key={part}>
                <h2 className="text-lg font-semibold tracking-tight">
                  {DOC_PART_LABELS[part]}
                </h2>
                <ul className="mt-3 space-y-3">
                  {hubs.map((hub) => (
                    <li key={hub.slug} className="fft-paper-panel px-4 py-3">
                      <Link
                        href={`/docs/${hub.slug}`}
                        className="font-medium text-primary hover:underline"
                      >
                        {hub.title}
                      </Link>
                      <p className="mt-1 text-sm text-base-content/70">
                        {hub.summary}
                      </p>
                      {hub.children?.length ? (
                        <ul className="mt-2 grid gap-1 sm:grid-cols-2">
                          {hub.children.map((child) => (
                            <li key={child.slug}>
                              <Link
                                href={`/docs/${child.slug}`}
                                className="link link-hover text-sm"
                              >
                                {child.title}
                              </Link>
                            </li>
                          ))}
                        </ul>
                      ) : null}
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </section>
      </div>
    </ShellDocs>
  );
}
