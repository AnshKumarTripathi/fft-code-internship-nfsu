import Link from "next/link";
import { displayValue, formatUtc, shortId } from "@/lib/format";
import type { EntityMeta } from "@/lib/types";

type CardEntityMetaProps = {
  entity: EntityMeta;
};

export function CardEntityMeta({ entity }: CardEntityMetaProps) {
  const title =
    displayValue(entity.label) !== "—"
      ? String(entity.label)
      : entity.entity_id;

  return (
    <header className="flex flex-col gap-4">
      <p className="text-xs uppercase tracking-wide text-base-content/60">
        <Link href="/incidents" className="link normal-case tracking-normal">
          Triage
        </Link>
        {" / "}
        <Link href="/entities" className="link normal-case tracking-normal">
          Entities
        </Link>
        {" / "}
        <span className="fft-mono-meta normal-case" title={entity.entity_id}>
          {shortId(entity.entity_id)}
        </span>
      </p>
      <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
      <p className="max-w-2xl text-sm text-base-content/70">
        Entity profile from the warehouse. Use Analysis for charts and Events
        for parsed logs.
      </p>
      <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <div>
          <dt className="text-xs uppercase tracking-wide text-base-content/60">
            Entity id
          </dt>
          <dd className="text-sm" title={entity.entity_id}>
            {entity.entity_id}
          </dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wide text-base-content/60">
            Type
          </dt>
          <dd>{displayValue(entity.entity_type)}</dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wide text-base-content/60">
            First seen (UTC)
          </dt>
          <dd className="fft-mono-meta">{formatUtc(entity.first_seen)}</dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wide text-base-content/60">
            Last seen (UTC)
          </dt>
          <dd className="fft-mono-meta">{formatUtc(entity.last_seen)}</dd>
        </div>
      </dl>
    </header>
  );
}
