import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { PART_F_PAGES } from "../content/docs/part-f.ts";

const PART_F_SLUGS = [
  "reference",
  "reference/routes",
  "reference/kpis",
  "reference/playbooks",
  "reference/troubleshooting",
  "reference/security",
  "reference/setup",
  "reference/versions",
  "reference/copilot-architecture",
  "reference/deeper-truth",
] as const;

describe("docs part F", () => {
  it("ships real bodies for every Part F slug", () => {
    for (const slug of PART_F_SLUGS) {
      const page = PART_F_PAGES[slug];
      assert.ok(page, `missing PART_F_PAGES entry for ${slug}`);
      assert.equal(page.stub, false);
      assert.ok(page.markdown.length > 80);
      assert.doesNotMatch(page.markdown, /Coming in v9/);
    }
  });

  it("covers routes, playbooks, troubleshooting, and security", () => {
    const routes = PART_F_PAGES["reference/routes"].markdown;
    assert.match(routes, /\/docs/);
    assert.match(routes, /\/analyses\/\[id\]/);

    const playbooks = PART_F_PAGES["reference/playbooks"].markdown;
    assert.match(playbooks, /Investigate a rate burst/);
    assert.match(playbooks, /changepoint/);

    const trouble = PART_F_PAGES["reference/troubleshooting"].markdown;
    assert.match(trouble, /CORS/);
    assert.match(trouble, /NEXT_PUBLIC_API_BASE/);

    const security = PART_F_PAGES["reference/security"].markdown;
    assert.match(security, /no login/i);
  });

  it("documents copilot Pocket Flow orchestration", () => {
    const arch = PART_F_PAGES["reference/copilot-architecture"].markdown;
    assert.match(arch, /PackContext/);
    assert.match(arch, /flow\.py/);
    assert.match(arch, /insight_flow\.py/);
    assert.match(arch, /get_incident_brief/);
    assert.match(arch, /```mermaid/);
  });
});
