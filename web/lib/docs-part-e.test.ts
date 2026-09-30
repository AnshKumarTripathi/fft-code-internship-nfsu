import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { PART_E_PAGES } from "../content/docs/part-e.ts";

const PART_E_SLUGS = [
  "pipeline",
  "pipeline/stages",
  "pipeline/warehouse",
  "pipeline/snapshots",
  "pipeline/config",
  "pipeline/large-corpus",
  "pipeline/log-families",
  "pipeline/single-writer",
] as const;

describe("docs part E", () => {
  it("ships real bodies for every Part E slug", () => {
    for (const slug of PART_E_SLUGS) {
      const page = PART_E_PAGES[slug];
      assert.ok(page, `missing PART_E_PAGES entry for ${slug}`);
      assert.equal(page.stub, false);
      assert.ok(page.markdown.length > 100);
      assert.doesNotMatch(page.markdown, /Coming in v9/);
    }
  });

  it("documents STAGE_ORDER and no UI threshold editor", () => {
    const stages = PART_E_PAGES["pipeline/stages"].markdown;
    assert.match(stages, /normalize/);
    assert.match(stages, /detect-statistical/);
    assert.match(stages, /correlate/);
    assert.match(stages, /report/);

    const config = PART_E_PAGES["pipeline/config"].markdown;
    assert.match(config, /no in-UI threshold editor/i);
    assert.match(config, /pipeline\.yaml/);
    assert.match(config, /Raise \/ lower effects/i);
    assert.match(config, /statistical\.z_threshold/);
    assert.match(config, /If you \*\*increase\*\*/);
    assert.match(config, /correlation\.promotion\.mode/);
    assert.match(config, /normalize\.enabled/);

    const families = PART_E_PAGES["pipeline/log-families"].markdown;
    assert.match(families, /normalize/i);
    assert.match(families, /Not any-log/i);
    assert.match(families, /code\/README\.md/);
    assert.match(families, /Supported families/);
    assert.match(families, /Not supported/);
    assert.match(families, /\| Family \|/);
    assert.match(families, /zeek_conn/);
    assert.match(families, /\.pcap/);

    const large = PART_E_PAGES["pipeline/large-corpus"].markdown;
    assert.match(large, /50[\u202f ]?MiB|50 MiB/);
    assert.match(large, /Path A/);
    assert.match(large, /Path B/);
    assert.match(large, /run-sharded/);
    assert.match(large, /sharding\.enabled/);
    assert.match(large, /100[\u202f ]?GB|100 GB/);
  });
});
