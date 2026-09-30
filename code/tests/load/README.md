# STFT / warehouse load-test procedure (R6)

This is a **manual** procedure. It is not a pytest gate: a 5–10× series can take
minutes and a large RSS, which CI machines should not pay on every commit.

Cap behaviour (skip entity, do not OOM) **is** covered in CI by
`tests/test_r6_isolation.py::test_stft_cap_skips_huge_entity_without_scoring`.

## Baseline

Use a synthetic count series whose length matches a 30-day entity at the default
`bucketing.bucket_seconds: 600`:

- **Baseline buckets:** `4320` (30 days × 144 buckets/day)
- **STFT window:** 72 h → 432 buckets / window (same as `pipeline.yaml`)

Record wall time and peak RSS for `--scale 1` once on your lab machine.

## 5–10× run

From `code/`:

```bash
python scripts/load_test_spectral.py --baseline-buckets 4320 --scale 1
python scripts/load_test_spectral.py --baseline-buckets 4320 --scale 10
```

`--scale 10` is **43 200** buckets (~300 days). Expect STFT time and RSS to grow
roughly with series length. If the process is killed, lower `spectral.max_buckets_per_entity`
(default **100000**) so detect-spectral **skips** that entity instead of allocating
an unbounded STFT.

## What to write down

Copy the script’s `elapsed_s` and `peak_rss_mib` lines into your lab notes (and,
if you want a public record, a dated row in [`KNOWN_LIMITATIONS.md`](../../KNOWN_LIMITATIONS.md)).
Do not treat a single laptop run as a capacity rating for a shared server.

## Warehouse lock

Two concurrent `python -m src.pipeline run-all` processes against the same
`paths.db_path` must fail with `WarehouseBusyError` (sidecar
`warehouse.duckdb.writer.lock`). The dashboard read-only connection does not
take that lock; it still 503s if DuckDB itself is exclusive-locked by a writer.
