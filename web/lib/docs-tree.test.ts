import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  adjacentDocs,
  DOC_TREE,
  findDocNode,
  flattenDocTree,
} from "./docs-tree.ts";

describe("docs-tree", () => {
  it("reserves every Part A–F chapter slug", () => {
    const flat = flattenDocTree(DOC_TREE);
    assert.ok(flat.length >= 50, `expected full catalogue, got ${flat.length}`);
    const parts = new Set(flat.map((entry) => entry.part));
    assert.deepEqual([...parts].sort(), ["A", "B", "C", "D", "E", "F"]);
  });

  it("finds nested slugs and adjacent prev/next", () => {
    const node = findDocNode("maths/robust-z");
    assert.ok(node);
    assert.equal(node?.title, "Robust z / MAD");

    const { prev, next } = adjacentDocs("getting-started");
    assert.equal(prev, null);
    assert.equal(next?.slug, "getting-started/what-this-is");
  });
});
