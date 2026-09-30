import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { PART_B_PAGES } from "../content/docs/part-b.ts";

const PART_B_SLUGS = [
  "navigate",
  "navigate/shell",
  "navigate/pipeline",
  "navigate/analyses",
  "navigate/snapshots",
  "navigate/triage",
  "navigate/incident-detail",
  "navigate/charts",
  "navigate/entities",
  "navigate/runs",
  "navigate/reports",
  "navigate/investigation-path",
] as const;

describe("docs part B", () => {
  it("ships real bodies for every Part B slug", () => {
    for (const slug of PART_B_SLUGS) {
      const page = PART_B_PAGES[slug];
      assert.ok(page, `missing PART_B_PAGES entry for ${slug}`);
      assert.equal(page.stub, false, `${slug} should not be a stub`);
      assert.ok(page.markdown.length > 120, `${slug} body too short`);
      assert.doesNotMatch(
        page.markdown,
        /Coming in v9/,
        `${slug} still looks like a stub`,
      );
    }
  });

  it("mentions every primary product route family", () => {
    const blob = Object.values(PART_B_PAGES)
      .map((page) => page.markdown)
      .join("\n");
    for (const needle of [
      "`/`",
      "/incidents",
      "/analyses/",
      "/entities",
      "/runs",
      "/reports",
      "/docs",
    ]) {
      assert.match(blob, new RegExp(needle.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    }
  });

  it("documents every Analysis chart family with schematics", () => {
    const charts = PART_B_PAGES["navigate/charts"].markdown;
    for (const needle of [
      "Activity timeline",
      "PSD / Welch spectrum",
      "STFT heatmap",
      "Spectral features card",
      "HTML report SVGs",
      "/docs-figures/activity-timeline.svg",
      "/docs-figures/psd-spectrum.svg",
      "/docs-figures/stft-heatmap.svg",
      "/docs-figures/report-svgs.svg",
    ]) {
      assert.match(charts, new RegExp(needle.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    }
  });
});
