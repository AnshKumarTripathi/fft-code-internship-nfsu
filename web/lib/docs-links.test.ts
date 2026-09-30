import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { DETECTOR_ORDER } from "./detectors.ts";
import {
  docsChartsHref,
  docsConfigKnobsHref,
  docsDetectorHref,
  docsDetectorMapComplete,
  docsHomeHref,
  docsLargeCorpusHref,
  docsTroubleshootingHref,
  docsWhyFlaggedHref,
} from "./docs-links.ts";

describe("docs-links", () => {
  it("maps every Phase 67 detector id", () => {
    assert.equal(docsDetectorMapComplete(), true);
    for (const id of DETECTOR_ORDER) {
      const href = docsDetectorHref(id);
      assert.match(href, /^\/docs\/maths\//);
      assert.notEqual(href, docsHomeHref());
    }
  });

  it("fails closed for unknown detectors", () => {
    assert.equal(docsDetectorHref("not_a_real_detector"), "/docs");
  });

  it("exposes chart, why-flagged, and troubleshooting targets", () => {
    assert.match(docsChartsHref("stft"), /#stft-heatmap$/);
    assert.equal(docsWhyFlaggedHref(), "/docs/workflows/why-flagged");
    assert.equal(
      docsTroubleshootingHref(),
      "/docs/reference/troubleshooting",
    );
    assert.equal(docsConfigKnobsHref(), "/docs/pipeline/config");
    assert.equal(docsLargeCorpusHref(), "/docs/pipeline/large-corpus");
  });
});
