:root {
  --bg: #f7f6f3;
  --ink: #1a1a1a;
  --muted: #5c5a55;
  --rule: #d8d4cc;
  --surface: #ffffff;
  --accent: #0b6e4f;
  --critical: #8b1e1e;
  --high: #a14a00;
  --medium: #8a6d00;
  --low: #3d5a4c;
  --mono: "IBM Plex Mono", ui-monospace, monospace;
  --sans: "IBM Plex Sans", system-ui, sans-serif;
}

*,
*::before,
*::after {
  box-sizing: border-box;
}

body {
  margin: 0;
  padding: 1.5rem 1.25rem 2.5rem;
  font-family: var(--sans);
  color: var(--ink);
  background: var(--bg);
  line-height: 1.5;
  max-width: 880px;
}

h1 {
  font-size: 1.4rem;
  margin: 0 0 0.5rem;
}

h2 {
  font-size: 1.05rem;
  margin: 1.5rem 0 0.6rem;
}

h3 {
  font-size: 0.95rem;
  margin: 1rem 0 0.4rem;
}

.meta {
  color: var(--muted);
  font-size: 0.9rem;
}

.severity {
  display: inline-block;
  padding: 0.1rem 0.45rem;
  font-family: var(--mono);
  font-size: 0.8em;
}

.severity-critical { color: var(--critical); }
.severity-high { color: var(--high); }
.severity-medium { color: var(--medium); }
.severity-low { color: var(--low); }

table {
  width: 100%;
  border-collapse: collapse;
  background: var(--surface);
  font-size: 0.9rem;
  page-break-inside: avoid;
}

th,
td {
  text-align: left;
  padding: 0.4rem 0.55rem;
  border-bottom: 1px solid var(--rule);
  vertical-align: top;
}

th {
  color: var(--muted);
  font-weight: 600;
}

.mono {
  font-family: var(--mono);
  font-size: 0.85em;
}

.notes {
  color: var(--muted);
}

footer {
  margin-top: 2rem;
  color: var(--muted);
  font-size: 0.85rem;
}

.chart {
  margin: 0.75rem 0;
  border: 1px solid var(--rule);
  background: var(--surface);
  page-break-inside: avoid;
}

.chart svg {
  display: block;
  max-width: 100%;
  height: auto;
}

@media print {
  body {
    background: #ffffff;
    max-width: none;
  }
}
