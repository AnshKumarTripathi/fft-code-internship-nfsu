import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  entityIdFromPath,
  incidentIdFromPath,
  isEntitiesRoute,
  reportFilenameFromPath,
} from "./copilot.ts";

describe("incidentIdFromPath", () => {
  it("reads incident routes", () => {
    assert.equal(
      incidentIdFromPath("/incidents/03508601-825d-56eb-a3a6-bc12acc78ab4/overview"),
      "03508601-825d-56eb-a3a6-bc12acc78ab4",
    );
  });

  it("reads report html and md filenames", () => {
    assert.equal(
      incidentIdFromPath(
        "/reports/incident_03508601-825d-56eb-a3a6-bc12acc78ab4.html",
      ),
      "03508601-825d-56eb-a3a6-bc12acc78ab4",
    );
    assert.equal(incidentIdFromPath("/reports/incident_inc-1.md"), "inc-1");
  });

  it("returns null for unrelated routes", () => {
    assert.equal(incidentIdFromPath("/docs/getting-started"), null);
    assert.equal(incidentIdFromPath("/reports"), null);
  });
});

describe("reportFilenameFromPath", () => {
  it("returns bare report filename", () => {
    assert.equal(
      reportFilenameFromPath(
        "/reports/incident_03508601-825d-56eb-a3a6-bc12acc78ab4.html",
      ),
      "incident_03508601-825d-56eb-a3a6-bc12acc78ab4.html",
    );
  });
});

describe("entityIdFromPath", () => {
  it("reads entity detail routes", () => {
    assert.equal(entityIdFromPath("/entities/alice"), "alice");
    assert.equal(entityIdFromPath("/entities"), null);
  });
});

describe("isEntitiesRoute", () => {
  it("matches registry and detail", () => {
    assert.equal(isEntitiesRoute("/entities"), true);
    assert.equal(isEntitiesRoute("/entities/alice"), true);
    assert.equal(isEntitiesRoute("/incidents/x"), false);
  });
});
