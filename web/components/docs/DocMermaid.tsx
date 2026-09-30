"use client";

/**
 * Client-side Mermaid renderer for Docs fenced ```mermaid blocks.
 * Renders once per chart string; falls back to a pre block on error.
 */

import { useEffect, useId, useState } from "react";
import mermaid from "mermaid";

mermaid.initialize({
  startOnLoad: false,
  theme: "neutral",
  securityLevel: "strict",
  flowchart: {
    curve: "basis",
  },
});

type DocMermaidProps = {
  chart: string;
};

export function DocMermaid({ chart }: DocMermaidProps) {
  const reactId = useId().replace(/:/g, "");
  const [svg, setSvg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const renderId = `docs-mermaid-${reactId}`;

    async function renderChart() {
      try {
        const { svg: nextSvg } = await mermaid.render(renderId, chart.trim());
        if (!cancelled) {
          setSvg(nextSvg);
          setError(null);
        }
      } catch (err) {
        if (!cancelled) {
          setSvg(null);
          setError(err instanceof Error ? err.message : "Mermaid render failed");
        }
      }
    }

    void renderChart();
    return () => {
      cancelled = true;
    };
  }, [chart, reactId]);

  if (error) {
    return (
      <pre
        className="overflow-x-auto rounded-lg border border-warning/40 bg-base-200/80 p-4 font-mono text-sm leading-relaxed"
        role="status"
      >
        <code>{chart.trim()}</code>
      </pre>
    );
  }

  if (!svg) {
    return (
      <div
        className="flex min-h-40 items-center justify-center rounded-lg border border-base-300 bg-base-100 px-4 py-8 text-sm text-base-content/60"
        role="status"
      >
        Drawing pipeline diagram…
      </div>
    );
  }

  return (
    <figure
      className="overflow-x-auto rounded-lg border border-base-300 bg-base-100 p-4"
      aria-label="Pipeline workflow diagram"
    >
      <div
        className="mx-auto flex justify-center [&_svg]:max-w-full"
        dangerouslySetInnerHTML={{ __html: svg }}
      />
    </figure>
  );
}
