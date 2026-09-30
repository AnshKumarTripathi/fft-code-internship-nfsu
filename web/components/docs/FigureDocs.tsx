import { readFileSync } from "node:fs";
import { join } from "node:path";

const FIGURE_NAMES = new Set([
  "activity-timeline.svg",
  "psd-spectrum.svg",
  "stft-heatmap.svg",
  "cases-activity.svg",
  "report-svgs.svg",
]);

function loadFigureSvg(fileName: string): string {
  const path = join(process.cwd(), "public", "docs-figures", fileName);
  return readFileSync(path, "utf8").trim();
}

/** Map markdown image src → public/docs-figures file name, or null. */
export function docsFigureFileName(src: string): string | null {
  const match = /^\/docs-figures\/([a-z0-9-]+\.svg)$/i.exec(src.trim());
  if (!match) return null;
  const fileName = match[1].toLowerCase();
  return FIGURE_NAMES.has(fileName) ? fileName : null;
}

type FigureDocsProps = {
  fileName: string;
  alt: string;
};

/** Inline SVG so Docs figures never depend on a separate /public fetch. */
export function FigureDocs({ fileName, alt }: FigureDocsProps) {
  const raw = loadFigureSvg(fileName);
  const prefix = fileName.replace(/\.svg$/i, "");
  const svg = raw
    .replace(/\sid="title"/g, ` id="${prefix}-title"`)
    .replace(/\sid="desc"/g, ` id="${prefix}-desc"`)
    .replace(
      /aria-labelledby="title desc"/g,
      `aria-labelledby="${prefix}-title ${prefix}-desc"`,
    );
  return (
    <figure className="overflow-hidden rounded-lg border border-base-300 bg-base-100">
      <div
        className="docs-figure mx-auto w-full max-w-3xl bg-[#f7f6f2] [&_svg]:h-auto [&_svg]:w-full"
        dangerouslySetInnerHTML={{ __html: svg }}
      />
      {alt ? (
        <figcaption className="border-t border-base-300 px-3 py-2 text-sm text-base-content/70">
          {alt}
        </figcaption>
      ) : null}
    </figure>
  );
}
