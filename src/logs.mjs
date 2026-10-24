// --logs: count secret-hunting probes in an exported access log, or in a saved Cloudflare GraphQL
// Analytics response, before and after (T2). Pure: the CLI feeds it lines or rows. It prints counts
// and client families, never addresses.

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

// Cloudflare GraphQL Analytics (httpRequestsAdaptiveGroups): rows of { count, dimensions }, each one
// standing for `count` requests. For sites with no access log to export. Recipe and limits in
// docs/recipes.md.
const GROUP_FIELDS = {
  path: 'clientRequestPath', query: 'clientRequestQuery', method: 'clientRequestHTTPMethodName',
  status: 'edgeResponseStatus', ua: 'userAgent', addr: 'clientIP',
};
const isGroup = (x) => x && typeof x === 'object' && Number.isFinite(x.count) && x.dimensions && typeof x.dimensions === 'object';

/** One analytics row as { record, count }; record is null when the row has no path. A dimension the
 *  query left out is null for the user agent (unknown, not empty) and empty for the address. */
export function parseGroup(row) {
  const d = row.dimensions;
  const count = Math.max(0, Math.round(row.count));
  if (typeof d[GROUP_FIELDS.path] !== 'string') return { record: null, count };
  const q = d[GROUP_FIELDS.query];
  const query = typeof q === 'string' && q ? (q.startsWith('?') ? q : `?${q}`) : '';
  return {
    count,
    record: {
      path: d[GROUP_FIELDS.path].split('?')[0], query,
      ua: GROUP_FIELDS.ua in d ? String(d[GROUP_FIELDS.ua] ?? '') : null,
      addr: String(d[GROUP_FIELDS.addr] ?? ''),
      method: String(d[GROUP_FIELDS.method] ?? 'GET').toUpperCase(),
      status: Number(d[GROUP_FIELDS.status]) || 0,
    },
  };
}

/** A saved GraphQL Analytics response (or an array of them, one per day or zone) as
 *  { rows, errors }, or null when the text isn't one. Rows are found wherever they sit
 *  (data.viewer.zones[].httpRequestsAdaptiveGroups, under an alias, or a bare array). */
export function analyticsGroups(text) {
  let doc;
  try { doc = JSON.parse(text); } catch { return null; }
  if (!doc || typeof doc !== 'object') return null;
  const rows = [], errors = [];
  const walk = (x, depth) => {
    if (!x || typeof x !== 'object' || depth > 12) return;
    if (Array.isArray(x)) {
      if (x.length && x.every(isGroup)) { rows.push(...x); return; }
      for (const y of x) walk(y, depth + 1);
      return;
    }
    if (Array.isArray(x.errors)) for (const e of x.errors) if (e && typeof e.message === 'string') errors.push(e.message);
    for (const [k, v] of Object.entries(x)) if (k !== 'errors') walk(v, depth + 1);
  };
  walk(doc, 0);
  return rows.length || errors.length ? { rows, errors } : null;
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
 * Tally log lines (add) or analytics rows (addGroup) one at a time; result() gives the report.
 * Addresses are counted, never kept in the report.
 * tags: the strings the site's prank links carry in their query (--tag), whatever format the site chose;
 * a request whose query contains one counts as a prank link followed.
 */
export function logTally({ tags: wanted = [] } = {}) {
  let lines = 0, parsed = 0, notFound = 0, probeTotal = 0, otherMisses = 0, noUa = 0, uaUnknown = 0, disguised = 0;
  let groups = 0, groupsRead = 0; // analytics rows, when fed by addGroup instead of add
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
  const methodRequests = new Map(); // "METHOD path" -> [{ record, n }]
  const served = new Set(); // "METHOD path" that got a 2xx or a 3xx
  let methodsResolved = false;
  const add = (map, key, n) => map.set(key, (map.get(key) ?? 0) + n);
  // n identical requests counted as probes of this kind. ua is null when the data has no user agents.
  const countProbe = (r, kind, n) => {
    const ua = r.ua ?? '';
    probeTotal += n;
    if (r.addr) probeAddrs.add(r.addr);
    const named = ua.match(CRAWLER_NAMES)?.[0] ?? ua.match(SEARCH_NAMES)?.[0];
    if (named) { disguised += n; add(disguises, named.toLowerCase(), n); }
    if (!kinds.has(kind)) kinds.set(kind, { requests: 0, statuses: new Map(), families: new Map() });
    const k = kinds.get(kind);
    k.requests += n;
    add(k.statuses, r.status, n);
    add(k.families, r.ua === null ? 'User agent not in the data' : family(ua), n);
    if ((r.status >= 200 && r.status < 300) || r.status >= 500) add(hits, `${r.status} ${r.method} ${r.path.slice(0, 80)}`, n);
  };
  // One parsed request, or n identical ones (an analytics row).
  function addRecord(r, n) {
    parsed += n;
    const ua = r.ua ?? '';
    add(statuses, statusClass(r.status), n);
    if (r.status === 404) notFound += n;
    if (r.ua === null) uaUnknown += n;
    else if (!ua || ua === '-') noUa += n;
    const query = decodeQuery(r.query);
    for (const t of wanted) if (query.includes(t)) add(tags, t, n);
    const kind = probeKind(r);
    const methodKind = kind === `${r.method} requests`;
    if (methodKind) {
      const key = `${r.method} ${r.path}`;
      if (r.status >= 200 && r.status < 400) served.add(key);
      if (!methodRequests.has(key)) methodRequests.set(key, []);
      methodRequests.get(key).push({ record: r, n });
    }
    if (r.addr) {
      if (!perAddr.has(r.addr)) perAddr.set(r.addr, { requests: 0, probes: 0, misses: 0, paths: new Set(), noUa: 0 });
      const a = perAddr.get(r.addr);
      a.requests += n;
      if (kind && !methodKind) a.probes += n;
      else if (!kind && r.status >= 400 && r.status < 500) a.misses += n;
      if (a.paths.size < 5000) a.paths.add(r.path);
      if (r.ua !== null && (!ua || ua === '-')) a.noUa += n;
    }
    if (!kind) { if (r.status >= 400 && r.status < 500) otherMisses += n; return; }
    if (!methodKind) countProbe(r, kind, n);
  }
  return {
    add(line) {
      lines++;
      const r = parseLine(line);
      if (r) addRecord(r, 1);
    },
    /** One row of a GraphQL Analytics response: it stands for `count` requests. */
    addGroup(row) {
      groups++;
      const { record, count } = parseGroup(row);
      if (!record) return;
      groupsRead++;
      if (count) addRecord(record, count);
    },
    result() {
      // Unused methods: only a method and path the site never served counts.
      if (!methodsResolved) {
        methodsResolved = true;
        for (const [key, requests] of methodRequests) {
          if (served.has(key)) continue;
          for (const { record: r, n } of requests) {
            countProbe(r, `${r.method} requests`, n);
            if (r.addr) perAddr.get(r.addr).probes += n;
          }
        }
      }
      const sorted = (m) => Object.fromEntries([...m].sort((a, b) => b[1] - a[1]));
      const addrs = [...perAddr.values()];
      const busiest = addrs.sort((a, b) => b.requests - a.requests)[0];
      const scanners = addrs.filter((a) => a.requests >= 20 && (a.probes + a.misses) / a.requests >= 0.9);
      return {
        source: groups ? 'analytics groups' : 'log lines',
        ...(groups ? { groups: { rows: groups, read: groupsRead } } : {}),
        lines,
        parsed,
        statuses: sorted(statuses),
        not_found_share: parsed ? Math.round((notFound / parsed) * 100) : 0,
        breakdown: { probes: probeTotal, other_misses: otherMisses, rest: parsed - probeTotal - otherMisses },
        no_user_agent: noUa,
        user_agent_not_in_data: uaUnknown,
        addresses_in_data: perAddr.size > 0,
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
  const out = rep.groups
    ? [`Read ${rep.groups.read} of ${rep.groups.rows} analytics rows (${rep.groups.rows - rep.groups.read} without a path), standing for ${rep.parsed} requests.`,
      'Analytics counts are sampled estimates, and a query returns only its top rows: rare paths past its limit are missing, so treat these as a lower bound.']
    : [`Read ${rep.parsed} of ${rep.lines} log lines (${rep.lines - rep.parsed} not understood)`];
  out.push(`All traffic by status: ${Object.entries(rep.statuses).map(([s, n]) => `${s} ${n}`).join(', ') || 'none'}; ${rep.not_found_share}% were 404s`);
  out.push(`Breakdown: probes ${b.probes} (${share(b.probes, rep.parsed)}%), other misses ${b.other_misses} (${share(b.other_misses, rep.parsed)}%), everything else ${b.rest} (${share(b.rest, rep.parsed)}%)`);
  const who = [rep.addresses_in_data ? `Probes came from ${rep.probe_addresses} address${rep.probe_addresses === 1 ? '' : 'es'}.` : 'The data has no addresses, so there are no per-address counts.'];
  who.push(rep.user_agent_not_in_data < rep.parsed ? `${rep.no_user_agent} requests (${share(rep.no_user_agent, rep.parsed)}%) sent no user agent.` : 'The data has no user agents, so probes are not split by client.');
  out.push(who.join(' '));
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
