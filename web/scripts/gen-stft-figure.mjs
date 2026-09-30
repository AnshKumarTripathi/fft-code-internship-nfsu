import fs from "node:fs";

const VIRIDIS = [
  [68, 1, 84],
  [59, 82, 139],
  [33, 145, 140],
  [94, 201, 98],
  [253, 231, 37],
];

function colourFor(t) {
  const x = Math.min(1, Math.max(0, t));
  const scaled = x * (VIRIDIS.length - 1);
  const i = Math.min(VIRIDIS.length - 2, Math.floor(scaled));
  const local = scaled - i;
  const c0 = VIRIDIS[i];
  const c1 = VIRIDIS[i + 1];
  const r = Math.round(c0[0] + (c1[0] - c0[0]) * local);
  const g = Math.round(c0[1] + (c1[1] - c0[1]) * local);
  const b = Math.round(c0[2] + (c1[2] - c0[2]) * local);
  return `rgb(${r},${g},${b})`;
}

const nTime = 56;
const nFreq = 28;
const cellW = 9;
const cellH = 6;
const plotX = 72;
const plotY = 72;
const plotW = nTime * cellW;
const plotH = nFreq * cellH;

const rects = [];
for (let f = 0; f < nFreq; f += 1) {
  for (let t = 0; t < nTime; t += 1) {
    const periodBand = f / (nFreq - 1);
    const ridge = Math.exp(-Math.pow((periodBand - 0.28) / 0.09, 2));
    const harmonic = 0.45 * Math.exp(-Math.pow((periodBand - 0.55) / 0.08, 2));
    let power = 0.08 + 0.55 * ridge + harmonic;

    const mid = t / (nTime - 1);
    if (mid > 0.38 && mid < 0.68) {
      const bump = Math.sin(((mid - 0.38) / 0.3) * Math.PI);
      power += 0.35 * bump * Math.exp(-Math.pow((periodBand - 0.22) / 0.07, 2));
      power += 0.18 * bump * Math.exp(-Math.pow((periodBand - 0.48) / 0.1, 2));
    }

    if (t >= nTime - 3) {
      const speck = ((f * 17 + t * 13) % 7) / 7;
      power = 0.15 + 0.55 * speck;
    }

    if (t < 2 && f % 5 === 0) continue;

    power = Math.min(1, Math.max(0, power));
    const x = plotX + t * cellW;
    const y = plotY + f * cellH;
    rects.push(
      `<rect x="${x}" y="${y}" width="${cellW}" height="${cellH}" fill="${colourFor(power)}"/>`,
    );
  }
}

const legendStops = [0, 0.25, 0.5, 0.75, 1]
  .map((t) => `<stop offset="${t * 100}%" stop-color="${colourFor(t)}"/>`)
  .join("");

const midY = plotY + plotH / 2;
const remX = plotX + (nTime - 3) * cellW;

const svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 720 340" role="img" aria-labelledby="title desc">
  <title id="title">STFT heatmap schematic</title>
  <desc id="desc">Viridis-like STFT power matrix across time windows and period bins, with a mid-window energy change and a short last remainder column.</desc>
  <rect width="720" height="340" fill="#f7f6f2"/>
  <text x="24" y="28" fill="#1c1b19" font-family="IBM Plex Sans, Segoe UI, sans-serif" font-size="15" font-weight="600">STFT heatmap</text>
  <text x="24" y="48" fill="#5c5954" font-family="IBM Plex Sans, Segoe UI, sans-serif" font-size="11">Rows = period bins. Columns = time windows. Brighter = more power (capped matrix).</text>
  <rect x="${plotX - 1}" y="${plotY - 1}" width="${plotW + 2}" height="${plotH + 2}" fill="#f0eeea" stroke="#d8d4cc"/>
  ${rects.join("\n  ")}
  <text x="18" y="${midY}" fill="#5c5954" font-family="IBM Plex Mono, Consolas, monospace" font-size="10" transform="rotate(-90 18 ${midY})">period</text>
  <text x="${plotX}" y="${plotY - 8}" fill="#5c5954" font-family="IBM Plex Mono, Consolas, monospace" font-size="9">~24h</text>
  <text x="${plotX}" y="${plotY + plotH + 14}" fill="#5c5954" font-family="IBM Plex Mono, Consolas, monospace" font-size="9">earlier</text>
  <text x="${plotX + plotW / 2 - 12}" y="${plotY + plotH + 14}" fill="#5c5954" font-family="IBM Plex Mono, Consolas, monospace" font-size="9">time</text>
  <text x="${plotX + plotW - 28}" y="${plotY + plotH + 14}" fill="#5c5954" font-family="IBM Plex Mono, Consolas, monospace" font-size="9">later</text>
  <defs><linearGradient id="leg" x1="0" x2="1">${legendStops}</linearGradient></defs>
  <rect x="600" y="88" width="96" height="12" fill="url(#leg)" stroke="#d8d4cc"/>
  <text x="600" y="80" fill="#5c5954" font-family="IBM Plex Sans, Segoe UI, sans-serif" font-size="10">power</text>
  <text x="600" y="116" fill="#5c5954" font-family="IBM Plex Mono, Consolas, monospace" font-size="9">low</text>
  <text x="670" y="116" fill="#5c5954" font-family="IBM Plex Mono, Consolas, monospace" font-size="9">high</text>
  <rect x="${remX}" y="${plotY}" width="${3 * cellW}" height="${plotH}" fill="none" stroke="#c45c3a" stroke-width="1.5" stroke-dasharray="4 3"/>
  <text x="600" y="150" fill="#8a4b36" font-family="IBM Plex Sans, Segoe UI, sans-serif" font-size="10">Last short</text>
  <text x="600" y="164" fill="#8a4b36" font-family="IBM Plex Sans, Segoe UI, sans-serif" font-size="10">remainder</text>
  <text x="600" y="178" fill="#8a4b36" font-family="IBM Plex Sans, Segoe UI, sans-serif" font-size="10">(treat carefully)</text>
  <text x="24" y="310" fill="#5c5954" font-family="IBM Plex Sans, Segoe UI, sans-serif" font-size="10">Look for a band that changes across columns (energy or shape). Numeric table is always available.</text>
  <text x="24" y="326" fill="#5c5954" font-family="IBM Plex Sans, Segoe UI, sans-serif" font-size="10">Opened behind Show STFT heatmap. Matrix may truncate (128 x 200 cap).</text>
</svg>
`;

fs.writeFileSync("public/docs-figures/stft-heatmap.svg", svg, "utf8");
console.log("wrote cells", rects.length, "bytes", svg.length);
