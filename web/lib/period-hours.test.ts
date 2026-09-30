import assert from "node:assert/strict";
import { test } from "node:test";
import { formatPeriodHours, periodHours } from "./period-hours.ts";

test("periodHours maps daily rhythm at 600s buckets to ~24h", () => {
  // f = bucket_seconds / (24 * 3600) cycles per bucket → period 24 h
  const bucketSeconds = 600;
  const freq = bucketSeconds / (24 * 3600);
  const hours = periodHours(freq, bucketSeconds);
  assert.ok(hours !== null);
  assert.ok(Math.abs(hours! - 24) < 1e-9);
  assert.equal(formatPeriodHours(hours), "24.0");
});

test("periodHours returns null for DC and invalid inputs", () => {
  assert.equal(periodHours(0, 600), null);
  assert.equal(periodHours(-0.1, 600), null);
  assert.equal(periodHours(0.01, null), null);
  assert.equal(periodHours(0.01, 0), null);
  assert.equal(formatPeriodHours(null), "DC");
});
