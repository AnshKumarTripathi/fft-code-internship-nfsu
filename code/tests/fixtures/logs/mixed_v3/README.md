# Mixed v3 freeze corpus (Phase 36)

Drop these files into `data/raw/` for a three-family lab. Detectors are unchanged; this corpus is short, so `run-all` will ingest/parse/bucket and typically soft-skip correlate/report (cold start). Use `run-all --require complete` only on a long-history lab corpus.

| File | Expected `log_source` |
|---|---|
| `ssh_extended.log` | `ssh` |
| `security.txt` | `windows_security` |
| `pfsense.txt` | `firewall` |

SSH-only lab (Windows and firewall lines are detected but not parsed):

```yaml
ingestion:
  enabled_sources: [ssh]   # empty list = all registered families
```
