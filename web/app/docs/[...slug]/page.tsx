import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { DocArticle } from "@/components/docs/DocArticle";
import { ShellDocs } from "@/components/docs/ShellDocs";
import { getDocPage } from "@/content/docs/pages";
import { flattenDocTree } from "@/lib/docs-tree";

export const dynamic = "force-static";

type DocsSlugPageProps = {
  params: Promise<{ slug: string[] }>;
};

export function generateStaticParams(): { slug: string[] }[] {
  return flattenDocTree().map((entry) => ({
    slug: entry.slug.split("/"),
  }));
}

export async function generateMetadata({
  params,
}: DocsSlugPageProps): Promise<Metadata> {
  const { slug: parts } = await params;
  const slug = parts.join("/");
  const page = getDocPage(slug);
  if (!page) {
    return { title: "Docs · Log Anomaly" };
  }
  return {
    title: `${page.title} · Docs · Log Anomaly`,
    description: page.summary,
  };
}

export default async function DocsSlugPage({ params }: DocsSlugPageProps) {
  const { slug: parts } = await params;
  const slug = parts.join("/");
  const page = getDocPage(slug);
  if (!page) notFound();

  return (
    <ShellDocs activeSlug={slug}>
      <DocArticle page={page} />
    </ShellDocs>
  );
}
