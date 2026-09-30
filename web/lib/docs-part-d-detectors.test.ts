import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { DETECTOR_ORDER, DETECTOR_ROLES } from "./detectors.ts";
import { PART_D_DETECTOR_PAGES } from "../content/docs/part-d-detectors.ts";

const DETECTOR_SLUGS = [
  "maths/statistical",
  "maths/spectral",
  "maths/changepoint",
  "maths/seasonal",
  "maths/ml",
  "maths/cluster",
  "maths/correlate",
  "maths/comparison",
  "maths/failure-modes",
] as const;

describe("docs part D detectors", () => {
  it("ships real bodies for D5–D13", () => {
    for (const slug of DETECTOR_SLUGS) {
      const page = PART_D_DETECTOR_PAGES[slug];
      assert.ok(page, `missing PART_D_DETECTOR_PAGES entry for ${slug}`);
      assert.equal(page.stub, false);
      assert.ok(page.markdown.length > 120);
      assert.doesNotMatch(page.markdown, /Coming in v9/);
    }
  });

  it("covers every Phase 67 glossary detector role", () => {
    const blob = Object.values(PART_D_DETECTOR_PAGES)
      .map((page) => page.markdown)
      .join("\n");
    for (const id of DETECTOR_ORDER) {
      const role = DETECTOR_ROLES[id];
      assert.ok(role, `missing role for ${id}`);
      assert.match(
        blob,
        new RegExp(role.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
        `role ${role} (${id}) missing from Part D catalogue`,
      );
    }
  });
});
