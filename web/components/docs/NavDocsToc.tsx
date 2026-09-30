"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import {
  DOC_PART_LABELS,
  DOC_TREE,
  flattenDocTree,
  type DocFlatEntry,
  type DocPart,
} from "@/lib/docs-tree";

type NavDocsTocProps = {
  activeSlug?: string;
};

function matchesQuery(entry: DocFlatEntry, query: string): boolean {
  if (!query) return true;
  const hay = `${entry.title} ${entry.summary} ${entry.slug} ${DOC_PART_LABELS[entry.part]}`.toLowerCase();
  return hay.includes(query);
}

export function NavDocsToc({ activeSlug }: NavDocsTocProps) {
  const [query, setQuery] = useState("");
  const q = query.trim().toLowerCase();

  const flat = useMemo(() => flattenDocTree(DOC_TREE), []);
  const visible = useMemo(
    () => flat.filter((entry) => matchesQuery(entry, q)),
    [flat, q],
  );

  const byPart = useMemo(() => {
    const map = new Map<DocPart, DocFlatEntry[]>();
    for (const entry of visible) {
      const list = map.get(entry.part) ?? [];
      list.push(entry);
      map.set(entry.part, list);
    }
    return map;
  }, [visible]);

  const parts = Object.keys(DOC_PART_LABELS) as DocPart[];

  return (
    <div className="flex flex-col gap-3">
      <label className="form-control w-full">
        <span className="sr-only">Search docs</span>
        <input
          type="search"
          className="input input-bordered input-sm w-full"
          placeholder="Filter chapters…"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          aria-label="Filter documentation chapters"
        />
      </label>

      <nav aria-label="Docs table of contents" className="space-y-4 text-sm">
        <Link
          href="/docs"
          className={`block rounded-lg px-2 py-1.5 transition-colors ${
            !activeSlug
              ? "bg-primary/10 font-medium text-primary"
              : "text-base-content/80 hover:bg-base-200"
          }`}
        >
          Docs home
        </Link>

        {parts.map((part) => {
          const entries = byPart.get(part);
          if (!entries?.length) return null;
          return (
            <div key={part}>
              <p className="mb-1 px-2 text-xs font-semibold uppercase tracking-wide text-base-content/50">
                {part}. {DOC_PART_LABELS[part]}
              </p>
              <ul className="space-y-0.5">
                {entries.map((entry) => {
                  const active = entry.slug === activeSlug;
                  return (
                    <li key={entry.slug}>
                      <Link
                        href={entry.href}
                        className={`block rounded-lg py-1.5 transition-colors ${
                          entry.depth > 0 ? "pl-4" : "px-2 font-medium"
                        } ${
                          entry.depth > 0 ? "pr-2" : ""
                        } ${
                          active
                            ? "bg-primary/10 font-medium text-primary"
                            : "text-base-content/80 hover:bg-base-200"
                        }`}
                      >
                        {entry.title}
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </div>
          );
        })}

        {q && visible.length === 0 ? (
          <p className="px-2 text-base-content/60">No chapters match.</p>
        ) : null}
      </nav>
    </div>
  );
}
