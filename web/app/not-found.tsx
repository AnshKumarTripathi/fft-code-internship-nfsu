import Link from "next/link";

export default function NotFound() {
  return (
    <div role="alert" className="alert">
      <div className="flex w-full flex-col gap-3">
        <div>
          <p className="font-medium">Page not found</p>
          <p className="text-sm text-base-content/70">
            Try Pipeline, Triage, Entities, Runs, or Reports.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Link href="/" className="btn btn-primary btn-sm">
            Pipeline
          </Link>
          <Link href="/incidents" className="btn btn-ghost btn-sm">
            Triage
          </Link>
          <Link href="/entities" className="btn btn-ghost btn-sm">
            Entities
          </Link>
          <Link href="/runs" className="btn btn-ghost btn-sm">
            Runs
          </Link>
          <Link href="/reports" className="btn btn-ghost btn-sm">
            Reports
          </Link>
        </div>
      </div>
    </div>
  );
}
