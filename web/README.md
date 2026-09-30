# Investigation UI (version eight)

Next.js App Router + Tailwind + DaisyUI is the **product** investigation UI. The Python pipeline does **not** need Node. This app never opens DuckDB — only HTTP JSON from `/api/v1`.

**No login.** Do not publish Next and an open API together on a hostile network.

**Plan status:** [version seven](../docsm/version_seven/overall_plans.md) through [version twelve](../docsm/version_twelve/overall_plans.md) are **Complete** (Phases **56–99**). In-app Docs: `/docs` (Parts A–F + UI deep links). CLI `run-all` remains for power users.

**Assistive copilot (v12):** floating fab + panel; **Add to chat** (buttons + text selection); secrets only in `code/.env` via FastAPI — never `NEXT_PUBLIC_*`. How-to: `/docs/getting-started/copilot`. Code-level Pocket Flow map: `/docs/reference/copilot-architecture`.

## UI shell (Phase 68 Lab Paper)

Cool off-white DaisyUI theme `fft`, IBM Plex Sans/Mono, left rail nav on desktop (drawer on small screens). Analyses stay cards; incidents stay tables. Sticky analysis chrome on `/analyses/[id]`. Cosmetic only — no API or detector changes.

## Prerequisites

- **Node 20+** (this app)
- **Python 3.11+** API from [`../code/`](../code/) (`pip install -r requirements-api.txt`)
- A warehouse with incidents (start a run from **Pipeline** at `/`, or `python -m src.pipeline run-all` from `code/` through correlate)

## Environment

Copy `.env.local.example` to `.env.local`:

```bash
copy .env.local.example .env.local
```

On Unix: `cp .env.local.example .env.local`

```text
NEXT_PUBLIC_API_BASE=http://127.0.0.1:8000
```

The API must be up. Server Components fetch `${NEXT_PUBLIC_API_BASE}/api/v1/*` with `cache: "no-store"`.

## Two terminals

From the repo root (also see [`../scripts/dev-v4.ps1`](../scripts/dev-v4.ps1) / [`../scripts/dev-v4.sh`](../scripts/dev-v4.sh) for the API process):

Terminal 1 — API (`code/`):

```bash
cd code
pip install -r requirements-api.txt
uvicorn src.api.main:app --host 127.0.0.1 --port 8000
```

Terminal 2 — UI (`web/`):

```bash
cd web
npm install
npm run dev -- --port 3000
```

Open `http://127.0.0.1:3000` — **Pipeline** is the home page.

**Pipeline** — primary operator path: `/` (upload / stage, start `run-all`, stage progress). `/pipeline` redirects here. Use **Clear lab data** on Pipeline to wipe prior warehouse/runs/analyses (API `POST /api/v1/pipeline/lab-reset`). CLI `run-all` remains for power users. Node is not required for the Python batch stages themselves.  
**Triage** — incident queue lives at `/incidents`.  
**Legacy Jinja:** set `dashboard.serve_legacy_html: true` in `code/config/pipeline.yaml`.  
v3 log families are unchanged; v4–v8 add no new `log_source`.

## CORS

FastAPI `dashboard.cors_origins` must include the Next origin. Defaults:

- `http://127.0.0.1:3000`
- `http://localhost:3000`

If you change the Next port or host, add that origin in `code/config/pipeline.yaml`. Never use `*`.

## Routes

| Path | Role |
|---|---|
| `/` | Pipeline + analyses (name container, upload / stage, start run, progress) |
| `/pipeline` | Redirects to `/` |
| `/analyses/[id]` | Snapshot triage for one analysis container (Phase 66) |
| `/incidents` | Live warehouse triage: incident list + KPIs |
| `/incidents/[id]` | Incident overview (summary, anomalies, event preview) |
| `/incidents/[id]/analysis` | Incident charts (activity + PSD + optional STFT heatmap) |
| `/incidents/[id]/events` | Paginated timeline or edges (`?step=`, `?page=`) |
| `/entities` | Entity search |
| `/entities/[id]` | Entity overview (`start`, `end`, `pad_hours`) |
| `/entities/[id]/analysis` | Entity charts (activity + spectrum + optional STFT heatmap) |
| `/entities/[id]/events` | Paginated parsed events |
| `/runs` | Pipeline runs (+ live job banner when a UI job is active) |
| `/reports` | Report index (paginated) |
| `/reports/[filename]` | In-app HTML/Markdown viewer |
| `/docs` | In-app operator / mentor Docs home (static; works if API is down) |
| `/docs/[...slug]` | Docs chapter (Parts A–F catalogue; complete) |

Nav order: **Pipeline → Triage → Entities → Reports → Runs → Docs**.

HTML reports open in-app (iframe to the API, `Content-Disposition: inline`). Markdown is shown as preformatted text with a link to the HTML sibling. Raw file URLs remain `{NEXT_PUBLIC_API_BASE}/api/v1/reports/{filename}`. Next does not copy report bodies into `public/`. Re-run `python -m src.pipeline report` from `code/` after correlate so artifacts include v5 SVG charts and capped anomaly tables.

**Docs (v9 Complete):** chapters live under `content/docs/` + `lib/docs-tree.ts`. Deep links from UI chrome use `lib/docs-links.ts`. No DuckDB and no API fetch — open `/docs` even when uvicorn is stopped.

## Data and stack

- Next.js App Router, TypeScript, Tailwind CSS, DaisyUI
- **Server Components** fetch `/api/v1`; types keep FastAPI `snake_case`
- Charts are **client islands** (`ChartEntityActivity`, `ChartEntitySpectrum`, STFT heatmap disclosure)
- PSD caption uses **600** bucket seconds, matching default `bucketing.bucket_seconds` (not read from YAML)
- **No DuckDB** in this app

## Errors

| Symptom | What to do |
|---|---|
| “JSON API is not running” | Start uvicorn from `code/` on port 8000 |
| Warehouse busy (503) / job busy (409) | Wait for the in-process Pipeline job or CLI writer to finish; only one writer at a time |
| No incidents | Start a run from **Pipeline** (`/`), then open **Triage** (`/incidents`); or from `code/` run `python -m src.pipeline run-all` (through correlate) |
| Browser CORS errors | Ensure `dashboard.cors_origins` lists this origin |
| Copilot fab disabled / chat 503 | Dual-gate: `COPILOT_ENABLED=true` in `code/.env` **and** `copilot.enabled: true` in YAML; restart API |
| AI Insight file missing | `copilot.ai_insight.enabled: true` + provider up; re-run report (Jinja still writes if LLM down) |

## Build

```bash
npm run build
```

Local `next dev` is enough; Vercel/production hosting is not a product gate.

## Out of scope

See [version_twelve — Not in v12](../docsm/version_twelve/README.md#not-in-v12), [version_nine — Not in v9](../docsm/version_nine/README.md#not-in-v9), [version_eight — Not in v8](../docsm/version_eight/README.md#not-in-v8), and [version_seven — Not in v7](../docsm/version_seven/README.md#not-in-v7) (SSO, LLM-as-detector, cancel/queue, weighted promotion, force-graph, streaming, …).
