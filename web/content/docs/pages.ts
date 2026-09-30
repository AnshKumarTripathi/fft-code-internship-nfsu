/**
 * Phase 69+ — static Docs bodies.
 * Prefer overrides / part modules; missing slugs get an auto stub from DOC_TREE.
 * Full chapter text lands in Phases 70–76.
 */

import { PART_A_PAGES } from "./part-a";
import { PART_B_PAGES } from "./part-b";
import { PART_C_PAGES } from "./part-c";
import { PART_D_DETECTOR_PAGES } from "./part-d-detectors";
import { PART_D_FOUNDATION_PAGES } from "./part-d-foundations";
import { PART_E_PAGES } from "./part-e";
import { PART_F_PAGES } from "./part-f";
import {
  DOC_PART_LABELS,
  DOC_TREE,
  findDocNode,
  flattenDocTree,
  type DocNode,
} from "@/lib/docs-tree";

export type DocPage = {
  slug: string;
  title: string;
  partLabel: string;
  summary: string;
  contentPhase: number;
  /** true until the owning content phase ships real prose */
  stub: boolean;
  markdown: string;
};

/** Hand-written bodies. Key = slug. */
const DOC_OVERRIDES: Partial<
  Record<string, { markdown: string; stub?: boolean }>
> = {
  ...PART_A_PAGES,
  ...PART_B_PAGES,
  ...PART_C_PAGES,
  ...PART_D_FOUNDATION_PAGES,
  ...PART_D_DETECTOR_PAGES,
  ...PART_E_PAGES,
  ...PART_F_PAGES,
};

function autoStubMarkdown(node: DocNode): string {
  return [
    node.summary,
    "",
    "> Full chapter text is not written here yet.",
    "",
    "This page is reserved so navigation and deep links stay stable.",
    "Short “What is this?” blurbs on triage screens remain available meanwhile.",
  ].join("\n");
}

export function getDocPage(slug: string): DocPage | null {
  const node = findDocNode(slug);
  if (!node) return null;

  const override = DOC_OVERRIDES[slug];
  const stub = override?.stub ?? true;
  const markdown = override?.markdown ?? autoStubMarkdown(node);

  return {
    slug: node.slug,
    title: node.title,
    partLabel: DOC_PART_LABELS[node.part],
    summary: node.summary,
    contentPhase: node.contentPhase,
    stub,
    markdown,
  };
}

export function listDocPages(): DocPage[] {
  return flattenDocTree(DOC_TREE)
    .map((entry) => getDocPage(entry.slug))
    .filter((page): page is DocPage => page !== null);
}

export function filterDocPages(query: string): DocPage[] {
  const q = query.trim().toLowerCase();
  if (!q) return listDocPages();
  return listDocPages().filter((page) => {
    const hay = `${page.title} ${page.summary} ${page.partLabel} ${page.slug}`.toLowerCase();
    return hay.includes(q);
  });
}
