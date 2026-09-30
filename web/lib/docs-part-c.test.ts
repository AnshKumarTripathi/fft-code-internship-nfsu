import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { PART_C_PAGES } from "../content/docs/part-c.ts";

const PART_C_SLUGS = [
  "workflows",
  "workflows/end-to-end",
  "workflows/upload",
  "workflows/start-monitor",
  "workflows/containers",
  "workflows/triage",
  "workflows/why-flagged",
  "workflows/charts-as-evidence",
  "workflows/reports",
  "workflows/lab-reset",
  "workflows/cli",
] as const;

describe("docs part C", () => {
  it("ships real bodies for every Part C slug", () => {
    for (const slug of PART_C_SLUGS) {
      const page = PART_C_PAGES[slug];
      assert.ok(page, `missing PART_C_PAGES entry for ${slug}`);
      assert.equal(page.stub, false, `${slug} should not be a stub`);
      assert.ok(page.markdown.length > 120, `${slug} body too short`);
      assert.doesNotMatch(
        page.markdown,
        /Coming in v9/,
        `${slug} still looks like a stub`,
      );
    }
  });

  it("documents lab-reset and stage order essentials", () => {
    const reset = PART_C_PAGES["workflows/lab-reset"].markdown;
    assert.match(reset, /lab-reset/);
    assert.match(reset, /CLEAR/);
    assert.match(reset, /does \*\*not\*\* delete config/i);

    const monitor = PART_C_PAGES["workflows/start-monitor"].markdown;
    assert.match(monitor, /correlate/);
    assert.match(monitor, /detect-statistical/);
  });

  it("covers chart evidence cases for each detector family", () => {
    const charts = PART_C_PAGES["workflows/charts-as-evidence"].markdown;
    for (const needle of [
      "Rate / statistical",
      "Rhythm / spectral",
      "Level-shift / changepoint",
      "Seasonal residual",
      "Sequence / ML",
      "Cluster outlier",
      "Report SVGs",
      "/docs-figures/cases-activity.svg",
    ]) {
      assert.match(charts, new RegExp(needle.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    }
  });
});
