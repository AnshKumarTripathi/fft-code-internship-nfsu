/** Phase 69 — Docs catalogue tree (Parts A–F). Slugs are stable for Phases 70–77. */

export type DocPart = "A" | "B" | "C" | "D" | "E" | "F";

export type DocNode = {
  /** URL path under /docs/ (no leading slash), e.g. "maths/robust-z" */
  slug: string;
  title: string;
  part: DocPart;
  /** Phase that fills the body (stub until then). */
  contentPhase: number;
  /** Short TOC blurb */
  summary: string;
  children?: DocNode[];
};

export type DocFlatEntry = DocNode & {
  href: string;
  depth: number;
};

export const DOC_PART_LABELS: Record<DocPart, string> = {
  A: "Getting started",
  B: "Navigate the UI",
  C: "Workflows",
  D: "Maths & detection",
  E: "Data & pipeline",
  F: "Reference",
};

export const DOC_TREE: DocNode[] = [
  {
    slug: "getting-started",
    title: "Getting started",
    part: "A",
    contentPhase: 70,
    summary: "What this lab is, who it is for, first run, and the pipeline diagram.",
    children: [
      {
        slug: "getting-started/what-this-is",
        title: "What this system is",
        part: "A",
        contentPhase: 70,
        summary: "Batch log anomaly lab — not a SIEM or live streamer.",
      },
      {
        slug: "getting-started/audience",
        title: "Who it is for",
        part: "A",
        contentPhase: 70,
        summary: "People reviewing incidents on a local or lab network.",
      },
      {
        slug: "getting-started/quick-start",
        title: "Quick start",
        part: "A",
        contentPhase: 70,
        summary: "Name an analysis, land logs, run, open triage.",
      },
      {
        slug: "getting-started/concepts",
        title: "Concepts glossary",
        part: "A",
        contentPhase: 70,
        summary: "Analysis, corpus, incident, detector, robust z, snapshot.",
      },
      {
        slug: "getting-started/non-goals",
        title: "What this product does not do",
        part: "A",
        contentPhase: 70,
        summary: "No SSO, cancel/queue, streaming, or auto-blocking.",
      },
      {
        slug: "getting-started/copilot",
        title: "Assistive copilot",
        part: "A",
        contentPhase: 99,
        summary: "Floating Q/A + Add to chat + optional AI Insight — not a detector.",
      },
    ],
  },
  {
    slug: "navigate",
    title: "Navigate the UI",
    part: "B",
    contentPhase: 71,
    summary: "Every primary screen and the investigation click-path.",
    children: [
      {
        slug: "navigate/shell",
        title: "Shell & navigation",
        part: "B",
        contentPhase: 71,
        summary: "Rail, drawer, analysis chrome, Docs link.",
      },
      {
        slug: "navigate/pipeline",
        title: "Pipeline home",
        part: "B",
        contentPhase: 71,
        summary: "Upload, start run, stage progress, lab reset.",
      },
      {
        slug: "navigate/analyses",
        title: "Analyses list & cards",
        part: "B",
        contentPhase: 71,
        summary: "Named containers, digests, status, open triage.",
      },
      {
        slug: "navigate/snapshots",
        title: "Analysis snapshot triage",
        part: "B",
        contentPhase: 71,
        summary: "/analyses/[id] — historical container view.",
      },
      {
        slug: "navigate/triage",
        title: "Triage queue",
        part: "B",
        contentPhase: 71,
        summary: "KPIs, filters, detector badges, empty states.",
      },
      {
        slug: "navigate/incident-detail",
        title: "Incident detail",
        part: "B",
        contentPhase: 71,
        summary: "Overview, Why flagged, Analysis, Events tabs.",
      },
      {
        slug: "navigate/charts",
        title: "Charts",
        part: "B",
        contentPhase: 71,
        summary: "Activity, PSD, STFT, spectral features, report SVGs — how to read each.",
      },
      {
        slug: "navigate/entities",
        title: "Entities",
        part: "B",
        contentPhase: 71,
        summary: "Search, overview window, entity charts and events.",
      },
      {
        slug: "navigate/runs",
        title: "Runs",
        part: "B",
        contentPhase: 71,
        summary: "Stage history and live job banner.",
      },
      {
        slug: "navigate/reports",
        title: "Reports",
        part: "B",
        contentPhase: 71,
        summary: "Index and in-app HTML/Markdown viewer.",
      },
      {
        slug: "navigate/investigation-path",
        title: "Typical investigation path",
        part: "B",
        contentPhase: 71,
        summary: "Pipeline → triage → Why flagged → charts → events.",
      },
    ],
  },
  {
    slug: "workflows",
    title: "Operator workflows",
    part: "C",
    contentPhase: 72,
    summary: "How to run a lab session end to end.",
    children: [
      {
        slug: "workflows/end-to-end",
        title: "End-to-end lab workflow",
        part: "C",
        contentPhase: 72,
        summary: "Fresh session through triage and optional report.",
      },
      {
        slug: "workflows/upload",
        title: "Uploading & staging logs",
        part: "C",
        contentPhase: 72,
        summary: "Upload limits, staging, selecting an existing corpus.",
      },
      {
        slug: "workflows/start-monitor",
        title: "Starting & monitoring a run",
        part: "C",
        contentPhase: 72,
        summary: "Progress states, failures, single-flight busy lock.",
      },
      {
        slug: "workflows/containers",
        title: "Working with analysis containers",
        part: "C",
        contentPhase: 72,
        summary: "Re-runs create new containers; snapshots stay openable.",
      },
      {
        slug: "workflows/triage",
        title: "Triaging incidents",
        part: "C",
        contentPhase: 72,
        summary: "Filters, clickable KPIs, empty-queue diagnosis.",
      },
      {
        slug: "workflows/why-flagged",
        title: "Reading Why flagged",
        part: "C",
        contentPhase: 72,
        summary: "Roles, scores vs cutoff, playbooks.",
      },
      {
        slug: "workflows/charts-as-evidence",
        title: "Using charts as evidence",
        part: "C",
        contentPhase: 72,
        summary: "Per-detector chart cases; activity/PSD/STFT/report SVGs.",
      },
      {
        slug: "workflows/reports",
        title: "Reports",
        part: "C",
        contentPhase: 72,
        summary: "When to run report; caps and top-N.",
      },
      {
        slug: "workflows/lab-reset",
        title: "Lab reset",
        part: "C",
        contentPhase: 72,
        summary: "Clear lab data — what is wiped.",
      },
      {
        slug: "workflows/cli",
        title: "CLI power-user path",
        part: "C",
        contentPhase: 72,
        summary: "Same stages via python -m src.pipeline.",
      },
    ],
  },
  {
    slug: "maths",
    title: "Maths & detection",
    part: "D",
    contentPhase: 73,
    summary: "Buckets, robust z, thresholds, and every detector.",
    children: [
      {
        slug: "maths/overview",
        title: "Pipeline maths overview",
        part: "D",
        contentPhase: 73,
        summary: "From buckets to scores to correlated incidents.",
      },
      {
        slug: "maths/approach",
        title: "Why multi-detector (approach)",
        part: "D",
        contentPhase: 73,
        summary:
          "Rate + rhythm + sequence complementarity; later additions; DF harness.",
      },
      {
        slug: "maths/bucketing",
        title: "Time bucketing",
        part: "D",
        contentPhase: 73,
        summary: "bucket_seconds, zero-fill, Nyquist intuition.",
      },
      {
        slug: "maths/robust-z",
        title: "Robust z / MAD",
        part: "D",
        contentPhase: 73,
        summary: "Shared scoring helper — not a Gaussian p-value.",
      },
      {
        slug: "maths/thresholds",
        title: "Threshold policy (4.0)",
        part: "D",
        contentPhase: 73,
        summary: "Lab convention cutoffs and binary flagging.",
      },
      {
        slug: "maths/worked-example",
        title: "Worked example (logs to flag)",
        part: "D",
        contentPhase: 73,
        summary: "Toy numbers: bucket counts, MAD, robust z, threshold.",
      },
      {
        slug: "maths/statistical",
        title: "Statistical (rate)",
        part: "D",
        contentPhase: 74,
        summary: "High-rate robust z on entity bucket counts.",
      },
      {
        slug: "maths/spectral",
        title: "Spectral (FFT / Welch / STFT)",
        part: "D",
        contentPhase: 74,
        summary: "Energy vs shape; remainder-window caveats.",
      },
      {
        slug: "maths/changepoint",
        title: "Changepoint (CUSUM)",
        part: "D",
        contentPhase: 74,
        summary: "Sustained level shifts in volume.",
      },
      {
        slug: "maths/seasonal",
        title: "Seasonal residual",
        part: "D",
        contentPhase: 74,
        summary: "Off the usual time-of-day profile.",
      },
      {
        slug: "maths/ml",
        title: "ML (IsolationForest / AE / ONNX)",
        part: "D",
        contentPhase: 74,
        summary:
          "Unsupervised sequence scoring; MLP autoencoder 32→8→32; optional IF+AE ensemble.",
      },
      {
        slug: "maths/cluster",
        title: "Cluster outlier",
        part: "D",
        contentPhase: 74,
        summary: "Peer-group outliers and cold-start honesty.",
      },
      {
        slug: "maths/correlate",
        title: "Correlation / ensemble",
        part: "D",
        contentPhase: 74,
        summary: "How detector hits become incidents.",
      },
      {
        slug: "maths/comparison",
        title: "Detector comparison table",
        part: "D",
        contentPhase: 74,
        summary: "Roles, cutoffs, strengths, and weak spots.",
      },
      {
        slug: "maths/failure-modes",
        title: "Known failure modes",
        part: "D",
        contentPhase: 74,
        summary: "Operator catalogue of misses and over-flags.",
      },
    ],
  },
  {
    slug: "pipeline",
    title: "Data & pipeline",
    part: "E",
    contentPhase: 75,
    summary: "Stages, warehouse, snapshots, config, single-writer.",
    children: [
      {
        slug: "pipeline/stages",
        title: "Stage order",
        part: "E",
        contentPhase: 75,
        summary: "ingest → … → correlate → report.",
      },
      {
        slug: "pipeline/warehouse",
        title: "Warehouse model",
        part: "E",
        contentPhase: 75,
        summary: "DuckDB + Parquet; Next never opens DuckDB.",
      },
      {
        slug: "pipeline/snapshots",
        title: "Snapshot vs live",
        part: "E",
        contentPhase: 75,
        summary: "Live refresh vs archived analysis containers.",
      },
      {
        slug: "pipeline/config",
        title: "Config knobs",
        part: "E",
        contentPhase: 75,
        summary:
          "YAML thresholds, policies, and raise/lower effects — not edited in UI.",
      },
      {
        slug: "pipeline/large-corpus",
        title: "Large corpus (100 GB)",
        part: "E",
        contentPhase: 75,
        summary:
          "Server-path sharding for huge logs — UI Path A and CLI Path B.",
      },
      {
        slug: "pipeline/log-families",
        title: "Supported log families",
        part: "E",
        contentPhase: 75,
        summary: "Supported parsers; no new families in recent releases.",
      },
      {
        slug: "pipeline/single-writer",
        title: "Single-writer / busy rules",
        part: "E",
        contentPhase: 75,
        summary: "One job at a time; no mid-run cancel.",
      },
    ],
  },
  {
    slug: "reference",
    title: "Reference",
    part: "F",
    contentPhase: 76,
    summary: "Routes, KPIs, playbooks, troubleshooting, security.",
    children: [
      {
        slug: "reference/routes",
        title: "Screen ↔ route map",
        part: "F",
        contentPhase: 76,
        summary: "Every product path and its role.",
      },
      {
        slug: "reference/kpis",
        title: "KPI & badge dictionary",
        part: "F",
        contentPhase: 76,
        summary: "Plain meanings for KPIs and detector roles.",
      },
      {
        slug: "reference/playbooks",
        title: "Playbook catalogue",
        part: "F",
        contentPhase: 76,
        summary: "Per-detector titles, hints, and actions.",
      },
      {
        slug: "reference/troubleshooting",
        title: "Troubleshooting",
        part: "F",
        contentPhase: 76,
        summary: "API down, CORS, empty queue, busy lock, failed stage.",
      },
      {
        slug: "reference/security",
        title: "Security & deployment",
        part: "F",
        contentPhase: 76,
        summary: "No auth; localhost or trusted LAN only.",
      },
      {
        slug: "reference/setup",
        title: "Dev setup (short)",
        part: "F",
        contentPhase: 76,
        summary: "Two terminals — API :8000 and Next :3000.",
      },
      {
        slug: "reference/versions",
        title: "Version history",
        part: "F",
        contentPhase: 76,
        summary: "Product history highlights.",
      },
      {
        slug: "reference/copilot-architecture",
        title: "Copilot orchestration",
        part: "F",
        contentPhase: 99,
        summary:
          "Code-level Pocket Flow chat + AI Insight: modules, nodes, tools, providers.",
      },
      {
        slug: "reference/deeper-truth",
        title: "Where deeper truth lives",
        part: "F",
        contentPhase: 76,
        summary: "Limitations, README, API docs, and this manual.",
      },
    ],
  },
];

function walk(
  nodes: DocNode[],
  depth: number,
  out: DocFlatEntry[],
): void {
  for (const node of nodes) {
    out.push({
      ...node,
      href: `/docs/${node.slug}`,
      depth,
    });
    if (node.children?.length) {
      walk(node.children, depth + 1, out);
    }
  }
}

/** Flattened chapter list in TOC / reading order (hubs + leaves). */
export function flattenDocTree(tree: DocNode[] = DOC_TREE): DocFlatEntry[] {
  const out: DocFlatEntry[] = [];
  walk(tree, 0, out);
  return out;
}

export function findDocNode(
  slug: string,
  tree: DocNode[] = DOC_TREE,
): DocNode | null {
  for (const node of tree) {
    if (node.slug === slug) return node;
    if (node.children?.length) {
      const found = findDocNode(slug, node.children);
      if (found) return found;
    }
  }
  return null;
}

export function docsHref(slug?: string): string {
  if (!slug) return "/docs";
  return `/docs/${slug}`;
}

export function adjacentDocs(slug: string): {
  prev: DocFlatEntry | null;
  next: DocFlatEntry | null;
} {
  const flat = flattenDocTree();
  const index = flat.findIndex((entry) => entry.slug === slug);
  if (index < 0) return { prev: null, next: null };
  return {
    prev: index > 0 ? flat[index - 1] : null,
    next: index < flat.length - 1 ? flat[index + 1] : null,
  };
}
