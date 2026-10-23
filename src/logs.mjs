// --logs: count secret-hunting probes in an exported access log, before and after (T2).
// Pure: the CLI feeds it lines. It prints counts and client families, never addresses.

import { probeFamily, knownProbe, OTHER_PROBE_FAMILIES, FRAMEWORK_ENDPOINTS } from './helpers.mjs';

// Well-known crawler and assistant names. A log can't verify them, but real crawlers don't probe:
// a probe under one of these names is a scanner wearing it (STANDARD.md §2).
export const CRAWLER_NAMES = /gptbot|chatgpt-user|oai-searchbot|claudebot|claude-user|claude-searchbot|perplexitybot|perplexity-user|google-extended|meta-externalagent|meta-externalfetcher|bytespider|ccbot|amazonbot|deepseekbot|grokbot|kimibot|duckassistbot|youbot|cohere-ai|mistralai-user|qwen|chatglm|hunyuan/i;
const SEARCH_NAMES = /googlebot|bingbot|applebot|duckduckbot|yandexbot|baiduspider/i;

// Client families, checked in order: the first match wins. A user agent is a claim, not proof:
// many probes claim to be Googlebot or GPTBot, so named crawlers are reported as "claims to be".
export const FAMILIES = [
  ['This audit (security-pranks-audit)', /^security-pranks-audit\//i],
  ['Claims to be a search crawler', /googlebot|bingbot|applebot|duckduckbot|yandexbot|baiduspider/i],
  ['Claims to be an AI crawler or assistant', CRAWLER_NAMES],
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
    if (/^https?:\/\//.test(path)) { try { const u = new URL(path); path = u.pathname + u.search; } catch { return null; } }
    return { path: path.split('?')[0], query: path.includes('?') ? path.slice(path.indexOf('?')) : '', ua: String(pick(o, FIELDS.ua) ?? ''), addr: String(pick(o, FIELDS.addr) ?? ''), method: String(pick(o, FIELDS.method) ?? 'GET').toUpperCase(), status: Number(pick(o, FIELDS.status)) || 0 };
  }
  const m = t.match(COMBINED);
  if (!m) return null;
  return { addr: m[1], method: m[2].toUpperCase(), path: m[3].split('?')[0], query: m[3].includes('?') ? m[3].slice(m[3].indexOf('?')) : '', status: Number(m[4]), ua: m[5] ?? '' };
}

const FRAMEWORK_PATHS = FRAMEWORK_ENDPOINTS.map((f) => [f.label, f.path.split('?')[0]]);

/** What a request was hunting for, or null for ordinary traffic. */
export function probeKind(r) {
  const fam = probeFamily(r.path);
  if (fam) return fam;
  const fw = FRAMEWORK_PATHS.find(([, p]) => r.path === p || r.path.startsWith(`${p}/`));
  if (fw) return `framework endpoint ${fw[0]}`;
  const other = knownProbe(r.path);
  if (other) return other;
  if (!['GET', 'HEAD'].includes(r.method)) return `${r.method} requests`;
  return null;
}

// Families a site might really serve (PHP pages, zip downloads): their counts can include real traffic.
const MAYBE_REAL = new Set(OTHER_PROBE_FAMILIES.map(([name]) => name).filter((n) => /PHP|backups/.test(n)));

const decodeQuery = (q) => { try { return decodeURIComponent(q ?? ''); } catch { return q ?? ''; } };
const statusClass = (s) => (s ? `${String(s)[0]}xx` : 'unknown');
const share = (n, of) => (of ? Math.round((n / of) * 1000) / 10 : 0);

/**
 * Tally lines one at a time; result() gives the report. Addresses are counted, never kept in the report.
 * tags: the strings the site's prank links carry in their query (--tag), whatever format the site chose;
 * a request whose query contains one counts as a prank link followed.
 */
export function logTally({ tags: wanted = [] } = {}) {
  let lines = 0, parsed = 0, notFound = 0, probeTotal = 0, otherMisses = 0, noUa = 0, disguised = 0;
  const disguises = new Map(); // claimed crawler name -> probes sent under it
  const statuses = new Map(); // class -> count, all traffic
  const kinds = new Map(); // kind -> { requests, statuses: Map, families: Map }
  const probeAddrs = new Set();
  const perAddr = new Map(); // addr -> { requests, probes, misses, paths: Set, noUa }
  const hits = new Map(); // "status method path" -> count, for probes that got 2xx or 5xx
  const tags = new Map(); // tag -> count, for prank links followed
  // Requests with a method other than GET or HEAD, held per "method path" until
  // the end: on a site with an API, POST /api/... is real traffic. A method and
  // path that got a 2xx or a 3xx anywhere in the log is one the site serves (a
  // form that POSTs and redirects answers 303), not a probe.
  const methodRequests = new Map(); // "METHOD path" -> [{ status, ua, addr }]
  const served = new Set(); // "METHOD path" that got a 2xx
  let methodsResolved = false;
  const countProbe = (r, kind) => {
    probeTotal++;
    if (r.addr) probeAddrs.add(r.addr);
    const named = r.ua.match(CRAWLER_NAMES)?.[0] ?? r.ua.match(SEARCH_NAMES)?.[0];
    if (named) { disguised++; disguises.set(named.toLowerCase(), (disguises.get(named.toLowerCase()) ?? 0) + 1); }
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
  };
  return {
    add(line) {
      lines++;
      const r = parseLine(line);
      if (!r) return;
      parsed++;
      statuses.set(statusClass(r.status), (statuses.get(statusClass(r.status)) ?? 0) + 1);
      if (r.status === 404) notFound++;
      if (!r.ua || r.ua === '-') noUa++;
      const query = decodeQuery(r.query);
      for (const t of wanted) if (query.includes(t)) tags.set(t, (tags.get(t) ?? 0) + 1);
      const kind = probeKind(r);
      const methodKind = kind === `${r.method} requests`;
      if (methodKind) {
        const key = `${r.method} ${r.path}`;
        if (r.status >= 200 && r.status < 400) served.add(key);
        if (!methodRequests.has(key)) methodRequests.set(key, []);
        methodRequests.get(key).push({ status: r.status, ua: r.ua, addr: r.addr, method: r.method, path: r.path });
      }
      if (r.addr) {
        if (!perAddr.has(r.addr)) perAddr.set(r.addr, { requests: 0, probes: 0, misses: 0, paths: new Set(), noUa: 0 });
        const a = perAddr.get(r.addr);
        a.requests++;
        if (kind && !methodKind) a.probes++;
        else if (!kind && r.status >= 400 && r.status < 500) a.misses++;
        if (a.paths.size < 5000) a.paths.add(r.path);
        if (!r.ua || r.ua === '-') a.noUa++;
      }
      if (!kind) { if (r.status >= 400 && r.status < 500) otherMisses++; return; }
      if (!methodKind) countProbe(r, kind);
    },
    result() {
      // Unused methods: only a method and path the site never served counts.
      if (!methodsResolved) {
        methodsResolved = true;
        for (const [key, requests] of methodRequests) {
          if (served.has(key)) continue;
          for (const r of requests) {
            countProbe(r, `${r.method} requests`);
            if (r.addr) perAddr.get(r.addr).probes++;
          }
        }
      }
      const sorted = (m) => Object.fromEntries([...m].sort((a, b) => b[1] - a[1]));
      const addrs = [...perAddr.values()];
      const busiest = addrs.sort((a, b) => b.requests - a.requests)[0];
      const scanners = addrs.filter((a) => a.requests >= 20 && (a.probes + a.misses) / a.requests >= 0.9);
      return {
        lines,
        parsed,
        statuses: sorted(statuses),
        not_found_share: parsed ? Math.round((notFound / parsed) * 100) : 0,
        breakdown: { probes: probeTotal, other_misses: otherMisses, rest: parsed - probeTotal - otherMisses },
        no_user_agent: noUa,
        probes: probeTotal,
        probe_addresses: probeAddrs.size,
        busiest_address: busiest ? { requests: busiest.requests, share: share(busiest.requests, parsed), probes_or_misses: share(busiest.probes + busiest.misses, busiest.requests), paths: busiest.paths.size, no_user_agent: busiest.noUa === busiest.requests } : null,
        scanner_addresses: { count: scanners.length, requests: scanners.reduce((n, a) => n + a.requests, 0) },
        kinds: [...kinds].map(([kind, k]) => ({ kind, requests: k.requests, may_include_real_traffic: MAYBE_REAL.has(kind), statuses: sorted(k.statuses), families: sorted(k.families) })).sort((a, b) => b.requests - a.requests),
        succeeded_or_crashed: [...hits].map(([key, n]) => ({ request: key, count: n })).sort((a, b) => b.count - a.count),
        prank_links_followed: wanted.length ? Object.fromEntries(wanted.map((t) => [t, tags.get(t) ?? 0])) : null,
        probes_under_crawler_names: { requests: disguised, names: sorted(disguises) },
      };
    },
  };
}

/** The report as text. */
export function formatLogs(rep) {
  const b = rep.breakdown;
  const out = [`Read ${rep.parsed} of ${rep.lines} log lines (${rep.lines - rep.parsed} not understood)`];
  out.push(`All traffic by status: ${Object.entries(rep.statuses).map(([s, n]) => `${s} ${n}`).join(', ') || 'none'}; ${rep.not_found_share}% were 404s`);
  out.push(`Breakdown: probes ${b.probes} (${share(b.probes, rep.parsed)}%), other misses ${b.other_misses} (${share(b.other_misses, rep.parsed)}%), everything else ${b.rest} (${share(b.rest, rep.parsed)}%)`);
  out.push(`Probes came from ${rep.probe_addresses} address${rep.probe_addresses === 1 ? '' : 'es'}. ${rep.no_user_agent} requests (${share(rep.no_user_agent, rep.parsed)}%) sent no user agent.`);
  if (rep.busiest_address) {
    const a = rep.busiest_address;
    out.push(`The busiest address sent ${a.requests} requests (${a.share}% of all traffic) for ${a.paths} different paths; ${a.probes_or_misses}% were probes or misses${a.no_user_agent ? ', all with no user agent' : ''}. A rate limit at the CDN suits an address like this.`);
  }
  if (rep.scanner_addresses.count) out.push(`${rep.scanner_addresses.count} address${rep.scanner_addresses.count === 1 ? '' : 'es'} sent 20 or more requests that were almost all probes or misses: ${rep.scanner_addresses.requests} requests together.`);
  out.push('');
  if (!rep.kinds.length) out.push('No probe requests.');
  for (const k of rep.kinds) {
    out.push(`${k.kind}  ${k.requests} request${k.requests === 1 ? '' : 's'} (${Object.entries(k.statuses).map(([s, n]) => `${s} ×${n}`).join(', ')})${k.may_include_real_traffic ? '  [includes real traffic if your site serves these]' : ''}`);
    for (const [fam, n] of Object.entries(k.families)) out.push(`  ${String(n).padStart(6)}  ${fam}`);
  }
  out.push('');
  if (rep.succeeded_or_crashed.length) {
    out.push('Probes that got a 2xx or a 5xx (P1, H1: each should be a 4xx):');
    for (const h of rep.succeeded_or_crashed.slice(0, 20)) out.push(`  ${String(h.count).padStart(6)}  ${h.request}`);
    if (rep.succeeded_or_crashed.length > 20) out.push(`  and ${rep.succeeded_or_crashed.length - 20} more`);
  } else out.push('Every probe got something other than a 2xx or a 5xx.');
  const d = rep.probes_under_crawler_names;
  if (d.requests) out.push('', `Probes sent under a well-known crawler's name: ${d.requests} (${Object.entries(d.names).slice(0, 8).map(([n, c]) => `${n} ${c}`).join(', ')}${Object.keys(d.names).length > 8 ? ', ...' : ''}). Real crawlers don't probe: these are scanners wearing the name. Answer the behavior, not the name (X3).`);
  if (rep.prank_links_followed) out.push('', 'Prank links followed (C1, T2):', ...Object.entries(rep.prank_links_followed).map(([t, n]) => `  ${String(n).padStart(6)}  ${t}`));
  else out.push('', 'To count visits through the prank\'s links, pass the tags they carry: --tag <text> (repeat for each).');
  out.push('', 'Run it on a day of logs before you ship and again after: scanner 5xx should drop to zero, and every probe should stay a failure (STANDARD.md, T2).');
  return out;
}
