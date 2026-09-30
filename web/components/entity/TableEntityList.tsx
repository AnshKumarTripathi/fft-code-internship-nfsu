import Link from "next/link";
import { NavPagination } from "@/components/layout/NavPagination";
import { displayValue, ENTITY_PAGE_SIZE, formatUtc } from "@/lib/format";
import { entityHref, entityListHref } from "@/lib/hrefs";
import type { EntityMeta } from "@/lib/types";

type TableEntityListProps = {
  items: EntityMeta[];
  q: string;
  total: number;
  offset: number;
};

export function TableEntityList({ items, q, total, offset }: TableEntityListProps) {
  const page = Math.floor(offset / ENTITY_PAGE_SIZE) + 1;
  const showingFrom = items.length ? offset + 1 : 0;
  const showingTo = offset + items.length;
  const totalPages = total ? Math.max(1, Math.ceil(total / ENTITY_PAGE_SIZE)) : 1;

  return (
    <section className="flex flex-col gap-4">
      <form className="flex flex-wrap items-end gap-3" method="get" action="/entities">
        <label className="form-control min-w-48 flex-1">
          <span className="label-text mb-1">Entity ID</span>
          <input
            id="q"
            type="search"
            name="q"
            className="input input-bordered input-sm"
            defaultValue={q}
            placeholder="alice"
            suppressHydrationWarning
          />
        </label>
        <button
          className="btn btn-sm btn-primary"
          type="submit"
          suppressHydrationWarning
        >
          Search
        </button>
        <Link className="btn btn-sm btn-ghost" href={entityListHref()}>
          Clear
        </Link>
      </form>

      {items.length === 0 ? (
        <div role="alert" className="alert">
          <span>
            {q
              ? `No entities matching ${q}.`
              : "No entities — run ingest."}
          </span>
        </div>
      ) : (
        <>
          <p className="text-sm opacity-70">
            Showing {showingFrom}–{showingTo} of {total}
          </p>
          <div className="fft-paper-panel overflow-x-auto">
            <table className="table table-sm">
              <thead>
                <tr className="text-xs uppercase tracking-wide text-base-content/60">
                  <th>Entity</th>
                  <th>Type</th>
                  <th>Label</th>
                  <th>First seen (UTC)</th>
                  <th>Last seen (UTC)</th>
                </tr>
              </thead>
              <tbody>
                {items.map((entity) => (
                  <tr key={entity.entity_id} className="hover">
                    <td>
                      <Link
                        className="link text-sm font-medium"
                        href={entityHref(entity.entity_id)}
                      >
                        {entity.entity_id}
                      </Link>
                    </td>
                    <td>{displayValue(entity.entity_type)}</td>
                    <td>{displayValue(entity.label)}</td>
                    <td className="fft-mono-meta">
                      {formatUtc(entity.first_seen)}
                    </td>
                    <td className="fft-mono-meta">
                      {formatUtc(entity.last_seen)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <NavPagination
            page={page}
            totalPages={totalPages}
            hrefForPage={(next) => entityListHref(q || undefined, next)}
            label="Entity pages"
          />
        </>
      )}
    </section>
  );
}
