/**
 * Minimal markdown for Docs chapters (no MDX dependency).
 * Supports: paragraphs, #–### headings, > blockquotes, `code`, **bold**,
 * [links](/path), ![images](/path), $inline$ / $$display$$ math (KaTeX),
 * fenced code (incl. ```mermaid), unordered (- ) and ordered (1. ) lists,
 * GFM pipe tables, blank-line separation.
 */

import Link from "next/link";
import type { ReactNode } from "react";
import {
  FigureDocs,
  docsFigureFileName,
} from "@/components/docs/FigureDocs";
import { DocMermaid } from "@/components/docs/DocMermaid";
import { renderDocMath } from "@/lib/doc-math";
import "katex/dist/katex.min.css";

function MathHtml({
  tex,
  displayMode,
}: {
  tex: string;
  displayMode: boolean;
}) {
  const html = renderDocMath(tex, { displayMode });
  if (displayMode) {
    return (
      <div
        className="docs-math-display my-4 overflow-x-auto py-1 text-center"
        dangerouslySetInnerHTML={{ __html: html }}
      />
    );
  }
  return (
    <span
      className="docs-math-inline"
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}

function inlineFormat(text: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  const pattern =
    /(\$\$[^$]+\$\$|\$[^$\n]+?\$|\*\*[^*]+\*\*|`[^`]+`|\[[^\]]+\]\([^)]+\))/g;
  let last = 0;
  let match: RegExpExecArray | null;
  let key = 0;

  while ((match = pattern.exec(text)) !== null) {
    if (match.index > last) {
      nodes.push(text.slice(last, match.index));
    }
    const token = match[0];
    if (token.startsWith("$$") && token.endsWith("$$")) {
      nodes.push(
        <MathHtml
          key={`md-${key++}`}
          tex={token.slice(2, -2)}
          displayMode
        />,
      );
    } else if (token.startsWith("$") && token.endsWith("$")) {
      nodes.push(
        <MathHtml
          key={`mi-${key++}`}
          tex={token.slice(1, -1)}
          displayMode={false}
        />,
      );
    } else if (token.startsWith("**")) {
      nodes.push(
        <strong key={`b-${key++}`}>{token.slice(2, -2)}</strong>,
      );
    } else if (token.startsWith("`")) {
      nodes.push(
        <code
          key={`c-${key++}`}
          className="rounded bg-base-200 px-1 font-mono text-sm"
        >
          {token.slice(1, -1)}
        </code>,
      );
    } else {
      const linkMatch = /^\[([^\]]+)\]\(([^)]+)\)$/.exec(token);
      if (linkMatch) {
        const href = linkMatch[2];
        const label = linkMatch[1];
        const external = /^https?:\/\//i.test(href);
        if (external) {
          nodes.push(
            <a
              key={`a-${key++}`}
              href={href}
              className="link link-primary"
              target="_blank"
              rel="noreferrer"
            >
              {label}
            </a>,
          );
        } else {
          nodes.push(
            <Link key={`a-${key++}`} href={href} className="link link-primary">
              {label}
            </Link>,
          );
        }
      }
    }
    last = match.index + token.length;
  }
  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
}

function slugifyHeading(text: string): string {
  return text
    .replace(/\$\$[^$]+\$\$/g, " ")
    .replace(/\$[^$\n]+?\$/g, " ")
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, "")
    .trim()
    .replace(/\s+/g, "-");
}

function isTableRow(line: string): boolean {
  const trimmed = line.trim();
  return trimmed.startsWith("|") && trimmed.includes("|", 1);
}

function isTableSeparator(line: string): boolean {
  const trimmed = line.trim();
  if (!trimmed.startsWith("|")) return false;
  const cells = trimmed
    .split("|")
    .slice(1, -1)
    .map((cell) => cell.trim());
  if (cells.length === 0) return false;
  return cells.every((cell) => /^:?-{3,}:?$/.test(cell));
}

function splitTableRow(line: string): string[] {
  const trimmed = line.trim().replace(/^\|/, "").replace(/\|$/, "");
  return trimmed.split("|").map((cell) => cell.trim());
}

type Block =
  | { type: "p"; text: string }
  | { type: "h"; level: 1 | 2 | 3; text: string }
  | { type: "quote"; text: string }
  | { type: "ul"; items: string[] }
  | { type: "ol"; items: string[] }
  | { type: "code"; text: string; lang?: string }
  | { type: "mermaid"; text: string }
  | { type: "img"; alt: string; src: string }
  | { type: "math"; tex: string }
  | { type: "table"; headers: string[]; rows: string[][] };

function parseBlocks(markdown: string): Block[] {
  const lines = markdown.replace(/\r\n/g, "\n").split("\n");
  const blocks: Block[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) {
      i += 1;
      continue;
    }

    if (line.trimStart().startsWith("```")) {
      const fence = line.trimStart().slice(3).trim().toLowerCase();
      const lang = fence.split(/\s+/)[0] || undefined;
      i += 1;
      const parts: string[] = [];
      while (i < lines.length && !lines[i].trimStart().startsWith("```")) {
        parts.push(lines[i]);
        i += 1;
      }
      if (i < lines.length) i += 1;
      const text = parts.join("\n");
      if (lang === "mermaid") {
        blocks.push({ type: "mermaid", text });
      } else {
        blocks.push({ type: "code", text, lang });
      }
      continue;
    }

    const trimmed = line.trim();
    if (trimmed.startsWith("$$")) {
      if (trimmed.endsWith("$$") && trimmed.length > 4) {
        blocks.push({ type: "math", tex: trimmed.slice(2, -2) });
        i += 1;
        continue;
      }
      i += 1;
      const parts: string[] = [];
      if (trimmed.length > 2) parts.push(trimmed.slice(2));
      while (i < lines.length && !lines[i].trim().endsWith("$$") && lines[i].trim() !== "$$") {
        parts.push(lines[i]);
        i += 1;
      }
      if (i < lines.length) {
        const closer = lines[i].trim();
        if (closer === "$$") {
          // ok
        } else if (closer.endsWith("$$")) {
          parts.push(closer.slice(0, -2));
        }
        i += 1;
      }
      blocks.push({ type: "math", tex: parts.join("\n") });
      continue;
    }

    const image = /^!\[([^\]]*)\]\(([^)]+)\)$/.exec(trimmed);
    if (image) {
      blocks.push({ type: "img", alt: image[1], src: image[2] });
      i += 1;
      continue;
    }

    const heading = /^(#{1,3})\s+(.+)$/.exec(line);
    if (heading) {
      blocks.push({
        type: "h",
        level: heading[1].length as 1 | 2 | 3,
        text: heading[2].trim(),
      });
      i += 1;
      continue;
    }

    if (line.trimStart().startsWith("> ")) {
      const parts: string[] = [];
      while (i < lines.length && lines[i].trimStart().startsWith("> ")) {
        parts.push(lines[i].trimStart().replace(/^>\s?/, ""));
        i += 1;
      }
      blocks.push({ type: "quote", text: parts.join(" ") });
      continue;
    }

    if (
      isTableRow(line) &&
      i + 1 < lines.length &&
      isTableSeparator(lines[i + 1])
    ) {
      const headers = splitTableRow(line);
      i += 2;
      const rows: string[][] = [];
      while (i < lines.length && isTableRow(lines[i]) && !isTableSeparator(lines[i])) {
        rows.push(splitTableRow(lines[i]));
        i += 1;
      }
      blocks.push({ type: "table", headers, rows });
      continue;
    }

    if (/^\s*-\s+/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\s*-\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*-\s+/, "").trim());
        i += 1;
      }
      blocks.push({ type: "ul", items });
      continue;
    }

    if (/^\s*\d+\.\s+/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*\d+\.\s+/, "").trim());
        i += 1;
      }
      blocks.push({ type: "ol", items });
      continue;
    }

    const parts: string[] = [];
    while (
      i < lines.length &&
      lines[i].trim() &&
      !lines[i].trimStart().startsWith("```") &&
      !lines[i].trim().startsWith("$$") &&
      !/^!\[[^\]]*\]\([^)]+\)$/.test(lines[i].trim()) &&
      !/^(#{1,3})\s+/.test(lines[i]) &&
      !lines[i].trimStart().startsWith("> ") &&
      !/^\s*-\s+/.test(lines[i]) &&
      !/^\s*\d+\.\s+/.test(lines[i]) &&
      !(
        isTableRow(lines[i]) &&
        i + 1 < lines.length &&
        isTableSeparator(lines[i + 1])
      )
    ) {
      parts.push(lines[i].trim());
      i += 1;
    }
    blocks.push({ type: "p", text: parts.join(" ") });
  }

  return blocks;
}

type DocMarkdownProps = {
  markdown: string;
  className?: string;
};

export function DocMarkdown({ markdown, className }: DocMarkdownProps) {
  const blocks = parseBlocks(markdown);

  return (
    <div className={className ?? "space-y-4 text-base leading-relaxed"}>
      {blocks.map((block, index) => {
        if (block.type === "h") {
          const id = slugifyHeading(block.text);
          const classNameByLevel =
            block.level === 1
              ? "text-2xl font-semibold tracking-tight"
              : block.level === 2
                ? "scroll-mt-24 text-xl font-semibold tracking-tight"
                : "scroll-mt-24 text-lg font-semibold tracking-tight";
          if (block.level === 1) {
            return (
              <h1 key={index} id={id} className={classNameByLevel}>
                {inlineFormat(block.text)}
              </h1>
            );
          }
          if (block.level === 2) {
            return (
              <h2 key={index} id={id} className={classNameByLevel}>
                {inlineFormat(block.text)}
              </h2>
            );
          }
          return (
            <h3 key={index} id={id} className={classNameByLevel}>
              {inlineFormat(block.text)}
            </h3>
          );
        }

        if (block.type === "quote") {
          return (
            <blockquote
              key={index}
              className="rounded-box border border-primary/40 bg-base-200/60 px-4 py-3 text-sm text-base-content/80"
            >
              {inlineFormat(block.text)}
            </blockquote>
          );
        }

        if (block.type === "ul") {
          return (
            <ul key={index} className="list-disc space-y-1 pl-5">
              {block.items.map((item, itemIndex) => (
                <li key={itemIndex}>{inlineFormat(item)}</li>
              ))}
            </ul>
          );
        }

        if (block.type === "ol") {
          return (
            <ol key={index} className="list-decimal space-y-2 pl-5">
              {block.items.map((item, itemIndex) => (
                <li key={itemIndex}>{inlineFormat(item)}</li>
              ))}
            </ol>
          );
        }

        if (block.type === "code") {
          return (
            <pre
              key={index}
              className="overflow-x-auto rounded-lg border border-base-300 bg-base-200/80 p-4 font-mono text-sm leading-relaxed"
            >
              <code>{block.text}</code>
            </pre>
          );
        }

        if (block.type === "mermaid") {
          return <DocMermaid key={index} chart={block.text} />;
        }

        if (block.type === "math") {
          return <MathHtml key={index} tex={block.tex} displayMode />;
        }

        if (block.type === "img") {
          const figureName = docsFigureFileName(block.src);
          if (figureName) {
            return (
              <FigureDocs
                key={index}
                fileName={figureName}
                alt={block.alt}
              />
            );
          }
          return (
            <figure
              key={index}
              className="overflow-hidden rounded-lg border border-base-300 bg-base-100"
            >
              {/* eslint-disable-next-line @next/next/no-img-element -- non-catalogue Docs images */}
              <img
                src={block.src}
                alt={block.alt}
                className="mx-auto h-auto w-full max-w-3xl bg-[#f7f6f2]"
                loading="lazy"
              />
              {block.alt ? (
                <figcaption className="border-t border-base-300 px-3 py-2 text-sm text-base-content/70">
                  {block.alt}
                </figcaption>
              ) : null}
            </figure>
          );
        }

        if (block.type === "table") {
          return (
            <div
              key={index}
              className="overflow-x-auto rounded-lg border border-base-300"
            >
              <table className="table table-zebra table-sm">
                <thead>
                  <tr>
                    {block.headers.map((header, headerIndex) => (
                      <th key={headerIndex} className="whitespace-nowrap">
                        {inlineFormat(header)}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {block.rows.map((row, rowIndex) => (
                    <tr key={rowIndex}>
                      {block.headers.map((_, cellIndex) => (
                        <td key={cellIndex}>
                          {inlineFormat(row[cellIndex] ?? "")}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          );
        }

        return <p key={index}>{inlineFormat(block.text)}</p>;
      })}
    </div>
  );
}
