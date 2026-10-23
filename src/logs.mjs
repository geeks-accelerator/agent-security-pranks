// --logs: count secret-hunting probes in an exported access log, before and after (T2).
// Pure: the CLI feeds it lines. It prints counts and client families, never addresses.

import { probeFamily, FRAMEWORK_ENDPOINTS } from './helpers.mjs';

// Client families, checked in order: the first match wins. A user agent is a claim, not proof:
// many probes claim to be Googlebot, so search crawlers are reported as "claims to be".
export const FAMILIES = [
  ['This audit (security-pranks-audit)', /^security-pranks-audit\//i],
  ['Claims to be a search crawler', /googlebot|bingbot|applebot|duckduckbot|yandexbot|baiduspider/i],
  ['AI crawlers and assistants', /gptbot|chatgpt-user|oai-searchbot|claudebot|claude-user|claude-searchbot|perplexitybot|perplexity-user|google-extended|meta-externalagent|bytespider|ccbot|amazonbot/i],
  ['Scripts', /^(curl|wget|python|node|undici|axios|go-http-client|okhttp|java\/|libwww|httpie|deno|bun\/|ruby|php|fasthttp)/i],
  ['Scanners that name themselves', /zgrab|nuclei|nmap|masscan|nikto|sqlmap|wpscan|gobuster|dirbuster|ffuf|censys|shodan|internet-measurement|expanse|leakix/i],
  ['Headless browsers', /headlesschrome|phantomjs|puppeteer|playwright|selenium/i],
  ['Other bots', /bot|crawl|spider|scan|fetch|probe/i],
  ['Browsers', /^mozilla\//i],
];

export function family(ua) {
  if (!ua || ua === '-') return 'No user agent';
  return FAMILIES.find(([, re]) => re.test(ua))?.[0] ?? 'Unidentified';
}

const COMBINED = /^(\S+) \S+ \S+ \[[^\]]*\] "(\S+) (\S+)[^"]*" (\d{3}) \S+(?: "[^"]*" "([^"]*)")?/;

// Field names per host's JSON lines: Cloudflare Logpush, Vercel log drains in NDJSON
// (proxy.path before the function's own path), Railway HTTP logs, then generic names.
const FIELDS = {
  path: ['ClientRequestPath', 'ClientRequestURI', 'proxy.path', 'path', 'requestPath', 'request_path', 'url', 'httpRequest.requestUrl'],
  ua: ['ClientRequestUserAgent', 'proxy.userAgent', 'userAgent', 'user_agent', 'clientUa', 'httpRequest.userAgent'],
  addr: ['ClientIP', 'proxy.clientIp', 'srcIp', 'clientIp', 'client_ip', 'ip', 'remote_addr', 'httpRequest.remoteIp'],
  method: ['ClientRequestMethod', 'proxy.method', 'method', 'httpRequest.requestMethod'],
  status: ['EdgeResponseStatus', 'proxy.statusCode', 'httpStatus', 'status', 'statusCode', 'httpRequest.status'],
};
const dig = (o, key) => key.split('.').reduce((x, k) => (x == null ? undefined : x[k]), o);
const pick = (o, keys) => { for (const k of keys) { const v = dig(o, k); if (v !== undefined && v !== null && v !== '') return Array.isArray(v) ? v[0] : v; } return undefined; };

/** One log line as { path, ua, addr, method, status }, or null. Combined log format and JSON lines. */
export function parseLine(line) {
  const t = line.trim();
  if (!t) return null;
  if (t.startsWith('{')) {
    let o;
    try { o = JSON.parse(t); } catch { return null; }
    let path = pick(o, FIELDS.path);
    if (typeof path !== 'string') return null;
    if (/^https?:\/\//.test(path)) { try { path = new URL(path).pathname; } catch { return null; } }
    return { path: path.split('?')[0], ua: String(pick(o, FIELDS.ua) ?? ''), addr: String(pick(o, FIELDS.addr) ?? ''), method: String(pick(o, FIELDS.method) ?? 'GET').toUpperCase(), status: Number(pick(o, FIELDS.status)) || 0 };
  }
  const m = t.match(COMBINED);
  if (!m) return null;
  return { addr: m[1], method: m[2].toUpperCase(), path: m[3].split('?')[0], status: Number(m[4]), ua: m[5] ?? '' };
}

const FRAMEWORK_PATHS = FRAMEWORK_ENDPOINTS.map((f) => [f.label, f.path.split('?')[0]]);

/** What a request was hunting for, or null for ordinary traffic. */
export function probeKind(r) {
  const fam = probeFamily(r.path);
  if (fam) return fam;
  const fw = FRAMEWORK_PATHS.find(([, p]) => r.path === p || r.path.startsWith(`${p}/`));
  if (fw) return `framework endpoint ${fw[0]}`;
  if (!['GET', 'HEAD'].includes(r.method)) return `${r.method} requests`;
  return null;
}

const statusClass = (s) => (s ? `${String(s)[0]}xx` : 'unknown');

/** Tally lines one at a time; result() gives the report. */
export function logTally() {
  let lines = 0, parsed = 0, notFound = 0, probeTotal = 0;
  const statuses = new Map(); // class -> count, all traffic
  const kinds = new Map(); // kind -> { requests, statuses: Map, families: Map }
  const addrs = new Set();
  const hits = new Map(); // "kind path status" -> count, for probes that got 2xx or 5xx
  return {
    add(line) {
      lines++;
      const r = parseLine(line);
      if (!r) return;
      parsed++;
      statuses.set(statusClass(r.status), (statuses.get(statusClass(r.status)) ?? 0) + 1);
      if (r.status === 404) notFound++;
      const kind = probeKind(r);
      if (!kind) return;
      probeTotal++;
      if (r.addr) addrs.add(r.addr);
      if (!kinds.has(kind)) kinds.set(kind, { requests: 0, statuses: new Map(), families: new Map() });
      const k = kinds.get(kind);
      k.requests++;
      k.statuses.set(r.status, (k.statuses.get(r.status) ?? 0) + 1);
      const fam = family(r.ua);
      k.families.set(fam, (k.families.get(fam) ?? 0) + 1);
      if ((r.status >= 200 && r.status < 300) || r.status >= 500) {
        const key = `${r.status} ${r.method} ${r.path.slice(0, 80)}`;
        hits.set(key, (hits.get(key) ?? 0) + 1);
      }
    },
    result() {
      const sorted = (m) => Object.fromEntries([...m].sort((a, b) => b[1] - a[1]));
      return {
        lines,
        parsed,
        statuses: sorted(statuses),
        not_found_share: parsed ? Math.round((notFound / parsed) * 100) : 0,
        probes: probeTotal,
        probe_addresses: addrs.size,
        kinds: [...kinds].map(([kind, k]) => ({ kind, requests: k.requests, statuses: sorted(k.statuses), families: sorted(k.families) })).sort((a, b) => b.requests - a.requests),
        succeeded_or_crashed: [...hits].map(([key, n]) => ({ request: key, count: n })).sort((a, b) => b.count - a.count),
      };
    },
  };
}

/** The report as text. */
export function formatLogs(rep) {
  const out = [`Read ${rep.parsed} of ${rep.lines} log lines (${rep.lines - rep.parsed} not understood)`];
  out.push(`All traffic by status: ${Object.entries(rep.statuses).map(([s, n]) => `${s} ${n}`).join(', ') || 'none'}; ${rep.not_found_share}% were 404s`);
  out.push(`Probes: ${rep.probes} request${rep.probes === 1 ? '' : 's'} from ${rep.probe_addresses} address${rep.probe_addresses === 1 ? '' : 'es'}`, '');
  if (!rep.kinds.length) out.push('No probe requests.');
  for (const k of rep.kinds) {
    out.push(`${k.kind}  ${k.requests} request${k.requests === 1 ? '' : 's'} (${Object.entries(k.statuses).map(([s, n]) => `${s} ×${n}`).join(', ')})`);
    for (const [fam, n] of Object.entries(k.families)) out.push(`  ${String(n).padStart(6)}  ${fam}`);
  }
  out.push('');
  if (rep.succeeded_or_crashed.length) {
    out.push('Probes that got a 2xx or a 5xx (P1, H1: each should be a 4xx):');
    for (const h of rep.succeeded_or_crashed.slice(0, 20)) out.push(`  ${String(h.count).padStart(6)}  ${h.request}`);
    if (rep.succeeded_or_crashed.length > 20) out.push(`  and ${rep.succeeded_or_crashed.length - 20} more`);
  } else out.push('Every probe got something other than a 2xx or a 5xx.');
  out.push('', 'Run it on a day of logs before you ship and again after: scanner 5xx should drop to zero, and every probe should stay a failure (STANDARD.md, T2).');
  return out;
}
