# Evaluation labels

CSV (or Parquet) files consumed by `python -m src.pipeline evaluate`. This directory ships a **synthetic** fixture only.

## Schema

| Column | Required | Notes |
|---|---|---|
| `entity_id` | yes | Matches warehouse `entities.entity_id` / detector rows |
| `window_start` | no | ISO-8601 UTC. Empty with empty `window_end` → entity-level label |
| `window_end` | no | ISO-8601 UTC |
| `label` | yes | `attacker` or `benign` |
| `attack_type` | no | Free text (e.g. `bruteforce`); ignored by overlap metrics |

Example: [synthetic_eval.csv](./synthetic_eval.csv), [demo_eval.csv](./demo_eval.csv) (matches `scripts/generate_demo_corpus.py` attack calendar)

`label` must be explicit. **Unlabeled entities are ignored** — they are not treated as benign. Only rows with `label=benign` are precision negatives.

Point `evaluation.labels_path` in `config/pipeline.yaml` at your file. See **Evaluate (Phase 15)**, **Threshold calibration (Phase 50)**, and **Optional LANL / CERT labels** in [`code/README.md`](../../../README.md).

Do **not** commit LANL, CERT, or other third-party datasets into this repo.
