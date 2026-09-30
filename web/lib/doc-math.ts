import katex from "katex";

type RenderMathOptions = {
  displayMode?: boolean;
};

/** Server-side KaTeX HTML for Docs equations. */
export function renderDocMath(
  tex: string,
  { displayMode = false }: RenderMathOptions = {},
): string {
  return katex.renderToString(tex.trim(), {
    displayMode,
    throwOnError: false,
    strict: "ignore",
    trust: false,
  });
}
