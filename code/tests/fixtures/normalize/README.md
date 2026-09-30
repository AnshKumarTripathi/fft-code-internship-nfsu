# Normalize fixtures (Phase 80–81)

| File | Source | Notes |
|---|---|---|
| `sample_security.evtx` | [python-evtx `tests/data/issue_38.evtx`](https://github.com/williballenthin/python-evtx) (public) | Tiny Security-channel EVTX (EventID 4672) for `evtx_text` |
| `sample.journal` | Synthetic corrupt bytes | Not a real systemd journal — exercises dead-letter / unavailable paths |

Regenerate EVTX on Windows (optional lab note):

```powershell
# Prefer a public tiny sample over exporting live host logs into the repo.
python scripts/export_evtx_fixture.py --help
```
