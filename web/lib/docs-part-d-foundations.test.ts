import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { PART_D_FOUNDATION_PAGES } from "../content/docs/part-d-foundations.ts";

const FOUNDATION_SLUGS = [
  "maths",
  "maths/overview",
  "maths/approach",
  "maths/bucketing",
  "maths/robust-z",
  "maths/thresholds",
  "maths/worked-example",
] as const;

describe("docs part D foundations", () => {
  it("ships real bodies for D1–D4, worked example, approach, and maths hub", () => {
    for (const slug of FOUNDATION_SLUGS) {
      const page = PART_D_FOUNDATION_PAGES[slug];
      assert.ok(page, `missing PART_D_FOUNDATION_PAGES entry for ${slug}`);
      assert.equal(page.stub, false);
      assert.ok(page.markdown.length > 120);
      assert.doesNotMatch(page.markdown, /Coming in v9/);
    }
  });

  it("approach page states complementarity tables for DF readers", () => {
    const approach = PART_D_FOUNDATION_PAGES["maths/approach"].markdown;
    assert.match(approach, /digital forensics/i);
    assert.match(approach, /Core complementarity/);
    assert.match(approach, /Later additions/);
    assert.match(approach, /Statistical/);
    assert.match(approach, /Spectral/);
    assert.match(approach, /\|\s*\*\*ML/);
    assert.match(approach, /Changepoint/);
    assert.match(approach, /Harness path/);
    assert.match(approach, /hypothesis generators/i);
  });

  it("matches robust z formula and threshold defaults", () => {
    const robust = PART_D_FOUNDATION_PAGES["maths/robust-z"].markdown;
    assert.match(robust, /0\.6745/);
    assert.match(robust, /10\^\{-9\}|1e-9/);
    assert.match(robust, /MAD/);
    assert.match(robust, /\$\$/);

    const thresholds = PART_D_FOUNDATION_PAGES["maths/thresholds"].markdown;
    assert.match(thresholds, /statistical\.z_threshold/);
    assert.match(thresholds, /changepoint\.decision_h/);
    assert.match(thresholds, /\*\*5\.0\*\*/);
    assert.match(thresholds, /lab convention/i);
  });

  it("ships a numeric logs-to-flag worked example", () => {
    const demo = PART_D_FOUNDATION_PAGES["maths/worked-example"].markdown;
    assert.match(demo, /\\mathbf\{c\}/);
    assert.match(demo, /14\.84/);
    assert.match(demo, /\\tau\s*=\s*4\.0|\\tau = 4\.0/);
    assert.match(demo, /0\.6745/);
    assert.match(demo, /bucket/i);
  });
});
