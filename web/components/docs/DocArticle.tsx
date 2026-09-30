import { ButtonAddToChat } from "@/components/copilot/ButtonAddToChat";
import { DocMarkdown } from "@/components/docs/DocMarkdown";
import { NavDocsPrevNext } from "@/components/docs/NavDocsPrevNext";
import { MAX_ATTACHMENT_CHARS } from "@/lib/copilot";
import type { DocPage } from "@/content/docs/pages";

type DocArticleProps = {
  page: DocPage;
};

function docsExcerpt(page: DocPage): string {
  const body = page.markdown.trim();
  const capped =
    body.length > MAX_ATTACHMENT_CHARS
      ? `${body.slice(0, MAX_ATTACHMENT_CHARS)}…`
      : body;
  return [`Docs: ${page.title}`, page.summary, "", capped].join("\n");
}

export function DocArticle({ page }: DocArticleProps) {
  return (
    <article className="min-w-0 max-w-3xl">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-xs uppercase tracking-wide text-base-content/60">
            Part {page.partLabel}
          </p>
          <h1 className="mt-1 text-3xl font-semibold tracking-tight">
            {page.title}
          </h1>
          <p className="mt-2 text-base text-base-content/70">{page.summary}</p>
        </div>
        <ButtonAddToChat
          label={`Docs: ${page.title}`}
          text={docsExcerpt(page)}
          slug={page.slug}
          route={`/docs/${page.slug}`}
          className="btn btn-ghost btn-sm shrink-0"
        />
      </div>

      {page.stub ? (
        <div className="alert mt-6 text-sm" role="status">
          <span>
            This chapter is reserved. Short “What is this?” blurbs on triage
            screens remain available meanwhile.
          </span>
        </div>
      ) : null}

      <div className="mt-8">
        <DocMarkdown markdown={page.markdown} />
      </div>

      <NavDocsPrevNext slug={page.slug} />
    </article>
  );
}
