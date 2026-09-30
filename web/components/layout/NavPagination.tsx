import Link from "next/link";

type NavPaginationProps = {
  page: number;
  totalPages: number;
  hrefForPage: (page: number) => string;
  label: string;
};

export function NavPagination({
  page,
  totalPages,
  hrefForPage,
  label,
}: NavPaginationProps) {
  if (totalPages <= 1) {
    return null;
  }
  return (
    <nav className="join" aria-label={label}>
      {page > 1 ? (
        <Link className="btn btn-sm join-item" href={hrefForPage(page - 1)}>
          Previous
        </Link>
      ) : (
        <span className="btn btn-sm join-item btn-disabled">Previous</span>
      )}
      <span className="btn btn-sm join-item pointer-events-none">
        Page {page} of {totalPages}
      </span>
      {page < totalPages ? (
        <Link className="btn btn-sm join-item" href={hrefForPage(page + 1)}>
          Next
        </Link>
      ) : (
        <span className="btn btn-sm join-item btn-disabled">Next</span>
      )}
    </nav>
  );
}
