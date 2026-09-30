/**
 * Convert Welch frequency (cycles per bucket) to period in hours.
 * Matches Phase 49 display formula: (1/f) * bucket_seconds / 3600 for f > 0.
 */
export function periodHours(
  freqCyclesPerBucket: number,
  bucketSeconds: number | null | undefined,
): number | null {
  if (
    !(freqCyclesPerBucket > 0) ||
    bucketSeconds == null ||
    !(bucketSeconds > 0)
  ) {
    return null;
  }
  return (1 / freqCyclesPerBucket) * (bucketSeconds / 3600);
}

/** Format period hours for axis ticks / table (1 decimal). */
export function formatPeriodHours(hours: number | null): string {
  if (hours === null) {
    return "DC";
  }
  if (!Number.isFinite(hours)) {
    return "—";
  }
  return hours.toFixed(1);
}
