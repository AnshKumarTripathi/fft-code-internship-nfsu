import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { PART_A_PAGES } from "../content/docs/part-a.ts";

const PART_A_SLUGS = [
  "getting-started",
  "getting-started/what-this-is",
  "getting-started/audience",
  "getting-started/quick-start",
  "getting-started/concepts",
  "getting-started/non-goals",
] as const;

describe("docs part A", () => {
  it("ships real bodies for every Part A slug", () => {
    for (const slug of PART_A_SLUGS) {
      const page = PART_A_PAGES[slug];
      assert.ok(page, `missing PART_A_PAGES entry for ${slug}`);
      assert.equal(page.stub, false, `${slug} should not be a stub`);
      assert.ok(page.markdown.length > 120, `${slug} body too short`);
      assert.doesNotMatch(
        page.markdown,
        /Coming in v9/,
        `${slug} still looks like a stub`,
      );
    }
  });

  it("ships a Getting started Mermaid pipeline diagram with normalize + detector fan-out", () => {
    const hub = PART_A_PAGES["getting-started"].markdown;
    assert.match(hub, /```mermaid/);
    assert.match(hub, /normalize/);
    assert.match(hub, /detect-statistical/);
    assert.match(hub, /detect-spectral/);
    assert.match(hub, /detect-ml/);
    assert.match(hub, /detect-changepoint/);
    assert.match(hub, /detect-seasonal/);
    assert.match(hub, /cluster/);
    assert.match(hub, /correlate/);
    assert.match(hub, /report/);
  });
});
