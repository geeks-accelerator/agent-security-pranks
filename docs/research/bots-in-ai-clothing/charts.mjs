// Renders the charts for docs/research/bots-in-ai-clothing.md as static SVG files, from data.json
// (the numbers behind the original interactive report). No dependencies:
//   node docs/research/bots-in-ai-clothing/charts.mjs
// Each chart sits on its own light card, so it reads the same in GitHub's light and dark themes.

import { readFileSync, writeFileSync } from 'node:fs';

const dir = new URL('./', import.meta.url);
const D = JSON.parse(readFileSync(new URL('data.json', dir), 'utf8'));

const C = {
  bg: '#ffffff', fg: '#1a2230', muted: '#5b6577', line: '#dde2ea', grid: '#eceff4',
  accent: '#2557c7', accentSoft: '#e6edfb', crit: '#c2362b', warn: '#b26a00', ok: '#217a4b',
  seg: ['#2557c7', '#8a5cd6', '#d4572b', '#c9a227', '#3a9a74', '#9aa3b2'],
};
const FONT = 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const fmt = (n) => (n >= 1e6 ? `${(n / 1e6).toFixed(2)}M` : n >= 1e4 ? `${Math.round(n / 1e3)}k` : n >= 1e3 ? `${(n / 1e3).toFixed(1)}k` : String(n));
const sum = (a) => a.reduce((x, y) => x + y, 0);

function svg(W, H, title, body, legend = []) {
  const keys = legend.map(([label, color], i) => `<rect x="${24 + i * 190}" y="44" width="11" height="11" rx="2" fill="${color}"/><text x="${40 + i * 190}" y="54" font-size="12" fill="${C.muted}">${esc(label)}</text>`).join('');
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" font-family="${FONT}" role="img" aria-label="${esc(title)}">
<rect x="0.5" y="0.5" width="${W - 1}" height="${H - 1}" rx="8" fill="${C.bg}" stroke="${C.line}"/>
<text x="24" y="30" font-size="15" font-weight="600" fill="${C.fg}">${esc(title)}</text>
${keys}
${body}
</svg>
`;
}
const text = (x, y, s, { size = 11, anchor = 'start', color = C.muted, weight = 400 } = {}) => `<text x="${x}" y="${y}" font-size="${size}" text-anchor="${anchor}" fill="${color}" font-weight="${weight}">${esc(s)}</text>`;
const niceMax = (v) => { const p = 10 ** Math.floor(Math.log10(v)); const m = v / p; return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 2.5 ? 2.5 : m <= 5 ? 5 : 10) * p; };

const START = Date.UTC(2026, 9, 16, 17); // the first hour, 2026-10-16 17:00 UTC
const DAYS = ['Fri', 'Sat', 'Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri'];

function timeSeries(file, title, layers, legend) {
  const W = 1000, H = 260, L = 64, R = 20, TOP = 70, B = 30, iw = W - L - R, ih = H - TOP - B;
  const max = niceMax(Math.max(...layers[0].data));
  const x = (i) => L + (i / (layers[0].data.length - 1)) * iw, y = (v) => TOP + ih - (v / max) * ih;
  let b = '';
  for (let k = 0; k <= 4; k++) { const v = (max * k) / 4; b += `<line x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}" stroke="${k ? C.grid : C.line}"/>${text(L - 8, y(v) + 4, fmt(v), { anchor: 'end' })}`; }
  for (let i = 0; i < 168; i++) {
    const d = new Date(START + i * 3600e3);
    if (d.getUTCHours() === 0) b += `<line x1="${x(i)}" x2="${x(i)}" y1="${TOP}" y2="${TOP + ih}" stroke="${C.grid}"/>${text(x(i) + 4, H - 10, `${DAYS[Math.floor((i + 17) / 24)]} ${d.getUTCMonth() + 1}/${d.getUTCDate()}`)}`;
  }
  for (const ly of layers) {
    const pts = ly.data.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(' ');
    b += `<polygon points="${L},${TOP + ih} ${pts} ${W - R},${TOP + ih}" fill="${ly.color}" fill-opacity="${ly.opacity}"/><polyline points="${pts}" fill="none" stroke="${ly.color}" stroke-width="1.4" stroke-linejoin="round"/>`;
  }
  const d = layers[0].data, pi = d.indexOf(Math.max(...d)), pd = new Date(START + pi * 3600e3);
  b += `<circle cx="${x(pi)}" cy="${y(d[pi])}" r="4" fill="${layers[0].color}"/>`;
  b += text(x(pi) + (pi > 120 ? -8 : 8), y(d[pi]) + 4, `Peak ${fmt(d[pi])}/hr, ${DAYS[Math.floor((pi + 17) / 24)]} ${String(pd.getUTCHours()).padStart(2, '0')}:00 UTC`, { anchor: pi > 120 ? 'end' : 'start', color: C.fg, weight: 500 });
  writeFileSync(new URL(file, dir), svg(W, H, title, b, legend));
}

function heatmap(file) {
  const W = 1000, L = 90, TOP = 80, cw = (W - L - 24) / 24, ch = 26, H = TOP + 8 * ch + 24;
  const max = Math.max(...D.P);
  let b = '';
  for (let h = 0; h < 24; h += 3) b += text(L + h * cw + cw / 2, TOP - 8, String(h).padStart(2, '0'), { anchor: 'middle' });
  for (let r = 0; r < 8; r++) {
    const date = new Date(Date.UTC(2026, 9, 16 + r));
    b += text(L - 10, TOP + r * ch + ch / 2 + 4, `${DAYS[r]} ${date.getUTCMonth() + 1}/${date.getUTCDate()}`, { anchor: 'end' });
    for (let h = 0; h < 24; h++) {
      const i = r * 24 + h - 17, has = i >= 0 && i < 168;
      b += `<rect x="${(L + h * cw + 1).toFixed(1)}" y="${TOP + r * ch + 1}" width="${(cw - 2).toFixed(1)}" height="${ch - 2}" rx="2" fill="${has ? C.crit : C.grid}" fill-opacity="${has ? (0.06 + (0.94 * D.P[i]) / max).toFixed(3) : 1}"/>`;
    }
  }
  writeFileSync(new URL(file, dir), svg(W, H, 'When probes arrive (UTC hour of day; darker = more probes)', b));
}

function hbars(file, title, rows, { segments, legend = [], labelWidth = 230 } = {}) {
  const W = 1000, TOP = legend.length ? 72 : 52, rowH = 24, H = TOP + rows.length * rowH + 16, L = 24 + labelWidth, R = 90, iw = W - L - R;
  const totals = rows.map((r) => (segments ? sum(r.slice(1)) : r[1]));
  const max = Math.max(...totals);
  let b = '';
  rows.forEach((r, i) => {
    const y = TOP + i * rowH;
    b += text(24, y + 13, r[0], { size: 12, color: C.fg });
    b += `<rect x="${L}" y="${y + 2}" width="${iw}" height="14" rx="2" fill="${C.grid}"/>`;
    let x = L;
    const parts = segments ? r.slice(1) : [r[1]];
    parts.forEach((v, j) => { const w = (v / max) * iw; if (w > 0) b += `<rect x="${x.toFixed(1)}" y="${y + 2}" width="${w.toFixed(1)}" height="14" fill="${segments ? segments[j] : C.accent}"/>`; x += w; });
    b += text(W - 24, y + 13, fmt(totals[i]), { anchor: 'end', size: 12, color: C.fg });
  });
  writeFileSync(new URL(file, dir), svg(W, H, title, b, legend));
}

function composition(file) {
  const rows = [['Browser-like', 2.88e6, 53.2], ['Scripts & headless browsers', 1.02e6, 18.9], ['Claims to be an AI bot', 588e3, 10.9], ['Other declared bots', 452e3, 8.4], ['Search engines & SEO tools', 363e3, 6.7], ['Empty or unrecognized', 106e3, 2.0]];
  const W = 1000, H = 200, L = 24, iw = W - 48;
  let b = '', x = L;
  rows.forEach(([, , pct], i) => { const w = (pct / 100) * iw; b += `<rect x="${x.toFixed(1)}" y="52" width="${w.toFixed(1)}" height="36" fill="${C.seg[i]}"/>`; x += w; });
  rows.forEach(([label, n, pct], i) => {
    const col = i % 2, row = Math.floor(i / 2), lx = L + col * 480, ly = 116 + row * 26;
    b += `<rect x="${lx}" y="${ly - 10}" width="11" height="11" rx="2" fill="${C.seg[i]}"/>${text(lx + 18, ly, label, { size: 12, color: C.fg })}${text(lx + 440, ly, `${fmt(n)}, ${pct}%`, { size: 12, anchor: 'end' })}`;
  });
  writeFileSync(new URL(file, dir), svg(W, H, 'What the traffic says it is (by user agent, 98% coverage)', b));
}

function scatter(file) {
  const CAT = { n: ['Local news', C.seg[0]], a: ['AI-agent platforms', C.seg[1]], c: ['Company & content', C.seg[4]], p: ['Parked & redirect', C.seg[2]] };
  const W = 1000, H = 400, L = 64, R = 24, TOP = 72, B = 46, iw = W - L - R, ih = H - TOP - B;
  const x = (v) => L + ((Math.log10(v) - 3) / 4) * iw, y = (s) => TOP + ih - (s / 70) * ih;
  let b = '';
  for (let s = 0; s <= 70; s += 10) b += `<line x1="${L}" x2="${W - R}" y1="${y(s)}" y2="${y(s)}" stroke="${s ? C.grid : C.line}"/>${text(L - 8, y(s) + 4, `${s}%`, { anchor: 'end' })}`;
  for (const [v, t] of [[1e3, '1k'], [1e4, '10k'], [1e5, '100k'], [1e6, '1M'], [1e7, '10M']]) b += `<line x1="${x(v)}" x2="${x(v)}" y1="${TOP}" y2="${TOP + ih}" stroke="${C.grid}"/>${text(x(v), TOP + ih + 16, t, { anchor: 'middle' })}`;
  b += text(L + iw / 2, H - 8, 'Requests per week (log scale)', { anchor: 'middle' });
  for (const [c, t, p] of D.pts) b += `<circle cx="${x(t).toFixed(1)}" cy="${y((p / t) * 100).toFixed(1)}" r="6" fill="${CAT[c][1]}" fill-opacity="0.8" stroke="${C.bg}" stroke-width="1.5"/>`;
  writeFileSync(new URL(file, dir), svg(W, H, 'Domain size vs. share of traffic that is probes (49 domains)', b, Object.values(CAT).map(([n, col]) => [n, col])));
}

function lorenz(file) {
  const W = 1000, H = 320, L = 64, R = 40, TOP = 52, B = 46, iw = W - L - R, ih = H - TOP - B;
  const x = (n) => L + (Math.log10(n) / Math.log10(3000)) * iw, y = (s) => TOP + ih - (s / 100) * ih;
  let b = '';
  for (let s = 0; s <= 100; s += 25) b += `<line x1="${L}" x2="${W - R}" y1="${y(s)}" y2="${y(s)}" stroke="${s ? C.grid : C.line}"/>${text(L - 8, y(s) + 4, `${s}%`, { anchor: 'end' })}`;
  for (const n of [1, 10, 100, 1000]) b += `<line x1="${x(n)}" x2="${x(n)}" y1="${TOP}" y2="${TOP + ih}" stroke="${C.grid}"/>${text(x(n), TOP + ih + 16, n.toLocaleString('en-US'), { anchor: 'middle' })}`;
  b += text(L + iw / 2, H - 8, 'Top N source addresses (log scale)', { anchor: 'middle' });
  const pts = D.lorenz.points.map(([n, c]) => [x(n), y((c / D.lorenz.total) * 100), n, c]);
  b += `<polygon points="${L},${TOP + ih} ${pts.map((p) => `${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(' ')} ${pts.at(-1)[0].toFixed(1)},${TOP + ih}" fill="${C.crit}" fill-opacity="0.12"/>`;
  b += `<polyline points="${pts.map((p) => `${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(' ')}" fill="none" stroke="${C.crit}" stroke-width="2"/>`;
  for (const [px, py, n, c] of pts) {
    b += `<circle cx="${px.toFixed(1)}" cy="${py.toFixed(1)}" r="3.5" fill="${C.crit}"/>`;
    if ([1, 10, 100, 2571].includes(n)) b += text(px + (n === 2571 ? -6 : 6), py - 8, `${n === 1 ? 'Top address' : n === 2571 ? 'All 2,571' : `Top ${n}`}: ${Math.round((c / D.lorenz.total) * 100)}%`, { anchor: n === 2571 ? 'end' : 'start', color: C.fg, weight: 500 });
  }
  writeFileSync(new URL(file, dir), svg(W, H, 'Cumulative share of probes by top source addresses', b));
}

timeSeries('requests-per-hour.svg', 'Requests per hour, all domains', [
  { data: D.T10.map((v) => v * 10), color: C.accent, opacity: 0.14 },
  { data: D.V10.map((v) => v * 10), color: C.seg[4], opacity: 0.5 },
], [['All requests', C.accent], ['Verified bots', C.seg[4]]]);
timeSeries('probes-per-hour.svg', 'Vulnerability probes per hour', [{ data: D.P, color: C.crit, opacity: 0.22 }]);
heatmap('probe-heatmap.svg');
hbars('impostor.svg', 'Requests by claimed crawler identity', D.imp, { segments: [C.ok, C.crit, C.warn], legend: [['Verified', C.ok], ['The impersonator', C.crit], ['Other unverified', C.warn]], labelWidth: 170 });
composition('user-agents.svg');
scatter('domain-scatter.svg');
hbars('probe-targets.svg', 'Probe targets (each probe counted once)', D.probeTargets);
hbars('countries.svg', 'Where probes come from (location of the sending address)', D.countries, { labelWidth: 170 });
lorenz('top-addresses.svg');
hbars('outcomes.svg', 'How the probes were answered (0 got a 2xx)', D.outcomes, { labelWidth: 170 });
console.log('wrote 10 charts');
