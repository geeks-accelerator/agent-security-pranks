// Pure helpers the checks share, tested without a network. Internal: the package exports only audit.mjs.

/**
 * The playbook's pattern for secret-hunting paths, matched against the URL-decoded, lowercased
 * path (decodedPath) so `/@fs/..%2f.env` and `/API/.ENV` count. The last alternative matches any
 * filename containing "credential", "secret" or "keys" with a file extension: safe only on a site
 * whose real pages never end in an extension (P6).
 */
export const SECRET_PROBE =
  /(^|\/|\.)\.?env($|[._\-:/]|\.[a-z0-9_-]+)|\/\.git(\/|$|-credentials)|\/\.ssh\/|\/id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$|\/\.aws\/|\/\.npmrc$|\/\.pgpass$|\/\.docker\/config\.json$|\/proc\/self\/environ|\/secrets?\.(env|json|ya?ml|toml)$|\/credentials(\.json|\.toml)?$|\/\.azure\/|wp-config\.php|\/[^/]*(credential|secret|[_-]keys)[^/]*\.(json|txt|zip|env|ya?ml|toml|ini|bak)$/;

export function decodedPath(pathname) {
  try { return decodeURIComponent(pathname).toLowerCase(); }
  catch { return pathname.toLowerCase(); }
}

export const isSecretProbe = (pathname) => SECRET_PROBE.test(decodedPath(pathname));

/** The paths the audit requests, one per family that showed up in the playbook's logs. */
export const PROBES = ['/.env', '/.env.production', '/.git/config', '/.ssh/id_rsa', '/.aws/credentials', '/wp-config.php', '/@fs/..%2f.env', '/API/.ENV'];

/**
 * Probe families for --logs, checked in order: the first match wins.
 * Each is a subset of SECRET_PROBE, so the audit and the log count can't drift apart.
 */
export const PROBE_FAMILIES = [
  ['env files', /(^|\/|\.)\.?env($|[._\-:/]|\.[a-z0-9_-]+)/],
  ['git', /\/\.git(\/|$|-credentials)/],
  ['SSH keys', /\/\.ssh\/|\/id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$/],
  ['cloud credentials', /\/\.aws\/|\/\.azure\/|\/credentials(\.json|\.toml)?$/],
  ['wp-config.php', /wp-config\.php/],
  ['process environment', /\/proc\/self\/environ/],
  ['package and database credentials', /\/\.npmrc$|\/\.pgpass$|\/\.docker\/config\.json$/],
  ['other secret files', /\/secrets?\.(env|json|ya?ml|toml)$|\/[^/]*(credential|secret|[_-]keys)[^/]*\.(json|txt|zip|env|ya?ml|toml|ini|bak)$/],
];

/** Which probe family a path belongs to, or null for a path that isn't a secret probe. */
export function probeFamily(pathname) {
  const p = decodedPath(pathname);
  if (!SECRET_PROBE.test(p)) return null;
  return PROBE_FAMILIES.find(([, re]) => re.test(p))?.[0] ?? 'other secret files';
}

/**
 * Other probe families for --logs: weak spots scanners hunt that aren't secret files. The audit
 * doesn't probe these (a site that serves PHP or zip downloads has real traffic here), so --logs
 * reports them on their own, with that caveat. Matched against the decoded, lowercased path.
 */
export const OTHER_PROBE_FAMILIES = [
  ['dev-server file reads', /\/@fs\/|\/__vite|\/api\/fs\/read/],
  ['other version-control and system files', /\/\.(svn|hg)(\/|$)|\/\.gitconfig$|\/\.ds_store$|\/\.bash_history$/],
  ['Spring actuator and heap dumps', /\/actuator(\/|$)|heapdump|\/jolokia(\/|$)/],
  ['infrastructure endpoints', /\/cgi-bin\/|\/k8s(\/|$)|\/alertmanager(\/|$)|\/payload\.config\.js$|\/\.kube\//],
  ['framework logs and debug pages', /laravel\.log$|\/storage\/logs\/|\/_profiler(\/|$)|\/telescope(\/|$)|phpinfo|\/debug\.log$|\/server-status$|\/elmah\.axd$/],
  ['backups and dumps', /\.(sql|bak|old|swp)$|\/(backup|www|site|db|database|dump)\.(zip|tar\.gz|tgz|rar|7z|sql)$|\/backups?(\/|$)/],
  ['WordPress and PHP', /\/wp-(admin|login|content|includes)|xmlrpc\.php|\.php($|\/)/],
];

/** Which probe family a path belongs to: a secret family first, then the others, else null. */
export function knownProbe(pathname) {
  const secret = probeFamily(pathname);
  if (secret) return secret;
  const p = decodedPath(pathname);
  return OTHER_PROBE_FAMILIES.find(([, re]) => re.test(p))?.[0] ?? null;
}

/**
 * Framework endpoints that answer even when no page uses them (H2). Each entry: how to tell the
 * framework from the homepage, how to tell the site uses the endpoint, and a request the endpoint
 * would answer with something other than 404 if it's live. The request asks the optimizer for a
 * remote image, which it rejects with 400 when it's live: a missing local file would answer 404
 * either way, and the check could never fail (the playbook's trap).
 */
export const FRAMEWORK_ENDPOINTS = [
  {
    framework: 'Next.js',
    detect: (home) => /next\.js/i.test(home.headers.get('x-powered-by') ?? '') || home.headers.has('x-nextjs-cache') || home.headers.has('x-nextjs-prerender') || /\/_next\/static\//.test(home.text),
    used: (home) => /\/_next\/image\?/.test(home.text),
    path: '/_next/image?url=https%3A%2F%2Fexample.com%2Fprobe.png&w=64&q=75',
    label: '/_next/image',
  },
];

// Credential shapes (P2). Each is a format a secret scanner would extract. The tests build their
// samples at run time, so this repo holds no string a scanner would flag.
export const CREDENTIAL_SHAPES = [
  ['AWS access key ID', /\b(AKIA|ASIA)[0-9A-Z]{16}\b/],
  ['GitHub token', /\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/],
  ['Slack token', /\bxox[abprs]-[A-Za-z0-9-]{10,}/],
  ['Stripe key', /\b[rs]k_(live|test)_[A-Za-z0-9]{16,}/],
  ['Anthropic or OpenAI key', /\bsk-(ant-)?[A-Za-z0-9_-]{20,}/],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/],
  ['npm token', /\bnpm_[A-Za-z0-9]{36}\b/],
  ['private key block', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ['JSON Web Token', /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/],
  ['URL with a username and password', /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@"']+:[^\s@/"']+@[^\s/"']+/i],
];

/** Shannon entropy in bits per character. */
export function entropy(s) {
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

/**
 * The credential shapes in a body, as a list of names (empty when there are none). Besides the
 * known formats, an assignment to a secret-sounding name (KEY, SECRET, TOKEN, PASSWORD...) whose
 * value is one long random-looking word counts: that's what a generic secret scanner extracts.
 * A URL, a path, a word, true/false or a sentence in quotes don't count.
 */
export function credentialShapes(text) {
  const found = new Set();
  for (const [name, re] of CREDENTIAL_SHAPES) if (re.test(text)) found.add(name);
  for (const m of String(text).matchAll(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*["']?([^\s"'#]+)["']?\s*(?:#.*)?$/gm)) {
    const [, name, value] = m;
    if (!/(key|secret|token|passw(or)?d|pwd|credential|auth|private)/i.test(name)) continue;
    if (/^(https?:\/\/|\/)/i.test(value) || value.length < 16) continue;
    if (/[A-Za-z]/.test(value) && /\d/.test(value) && entropy(value) >= 3.5) found.add(`random-looking value for ${name}`);
  }
  return [...found];
}

// Values that read as settings, not secrets: a person and a secret scanner both see them as such.
const PLAIN_VALUES = /^(true|false|yes|no|none|null|nil|public|open|off|on|required|optional|n\/a|-?\d+)$/i;

/**
 * Secret-named keys given a one-word value, like PASSWORD=feed-the-ferret-first (P2, a warning).
 * A person reads it as a joke; a generic secret scanner keys on the name and extracts the value.
 * Fine: a quoted phrase with spaces, a URL or path, or a plain setting (PASSWORD_REQUIRED=false).
 */
export function secretAssignments(text) {
  const found = [];
  for (const m of String(text).matchAll(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*(["']?)([^\n#]*?)\2\s*(?:#.*)?$/gm)) {
    const [, name, , value] = m;
    if (!/(^|_)(key|secret|token|passw(or)?d|pwd|pass|credentials?|auth|api_?key|private_?key)(_|$)/i.test(name)) continue;
    if (/\s/.test(value) || value.length < 6 || PLAIN_VALUES.test(value) || /^(https?:\/\/|\/)/i.test(value)) continue;
    found.push(name);
  }
  return [...new Set(found)];
}

/**
 * What's wrong with a prank's Cache-Control (P3), or null. no-store is best; a short shared cache
 * (a day or less) is fine and saves work when one address sends thousands of probes. Longer, or
 * none at all, and an old prank keeps answering after you change it, at the CDN's discretion.
 */
export const MAX_CACHE_SECONDS = 86400;
export function cacheProblem(header) {
  const h = String(header ?? '').toLowerCase();
  if (/no-store|no-cache|private/.test(h)) return null;
  if (!h) return 'no Cache-Control, so the CDN decides how long it lives';
  const ages = [...h.matchAll(/(?:s-maxage|max-age)\s*=\s*(\d+)/g)].map((m) => Number(m[1]));
  if (/immutable/.test(h)) return 'Cache-Control: immutable';
  if (!ages.length) return `Cache-Control: ${h} sets no lifetime`;
  const longest = Math.max(...ages);
  return longest > MAX_CACHE_SECONDS ? `cached for ${Math.round(longest / 3600)} hours (keep it to a day or less, or no-store)` : null;
}

/**
 * Lines in a prank that tell an agent to act (C2, a warning): a request to send, a command to run.
 * An invitation to the operator, with a link, keeps the joke without relying on an agent that
 * follows instructions it finds in a response.
 */
export function instructsAgent(text) {
  const t = String(text);
  const found = [];
  if (/\b(POST|PUT|PATCH|DELETE)\s+(https?:\/\/|\/)/.test(t)) found.push('a request to send');
  if (/\b(curl|wget)\b[^\n]*\shttps?:\/\//i.test(t)) found.push('a command to run');
  if (/\b(ignore|disregard)\s+(all\s+|your\s+)?(previous|prior)\s+(instructions|prompts?)/i.test(t)) found.push('an override of its instructions');
  return found;
}

/**
 * The CDN or firewall that blocked a request before it reached the site, or null. A block is a
 * safe failure (P1), but it isn't the site's prank, so the prank rules don't grade it.
 */
export function edgeBlock(r) {
  if (!(r.status >= 400 && r.status < 500)) return null;
  const h = r.headers;
  const title = String(r.text ?? '').match(/<title>([^<]*)<\/title>/i)?.[1] ?? '';
  if (h.has('cf-mitigated') || (/cloudflare/i.test(h.get('server') ?? '') && /attention required|just a moment|access denied|sorry, you have been blocked/i.test(title))) return 'Cloudflare';
  if (h.has('x-vercel-mitigated')) return 'Vercel firewall';
  if (/awselb|cloudfront/i.test(h.get('server') ?? '') && /^403 forbidden$|request blocked|error: the request could not be satisfied/i.test(title)) return 'AWS';
  if (/akamai/i.test(h.get('server') ?? '') && /access denied/i.test(title)) return 'Akamai';
  return null;
}

/** A link in a prank tagged so follow-through can be counted (C1, T2): ?ref=scanner-..., source=scanner:... */
export const SCANNER_TAG = /[?&](ref|source|utm_source)=scanner[-:_.\w]*/i;

/**
 * A probe answer with the requested path removed, so a page that echoes the path compares
 * equal to the site's ordinary 404 page.
 */
export function withoutPath(text, path) {
  let out = String(text ?? '');
  for (const p of new Set([path, decodedPath(path), (() => { try { return decodeURIComponent(path); } catch { return path; } })()])) {
    if (p) out = out.split(p).join('');
  }
  return out.replace(/\s+/g, ' ').trim();
}

/**
 * For --base: request a local or preview build as if it were the domain.
 * toBase() sends the site's URLs (the domain or its www twin) to the base;
 * fromBase() maps them back, so every check keeps seeing the domain's URLs.
 */
export function baseMapper(domain, base) {
  const hosts = new Set([domain, domain.startsWith('www.') ? domain.slice(4) : `www.${domain}`]);
  const baseOrigin = base ? new URL(base).origin : null;
  const toBase = (url) => {
    if (!baseOrigin) return url;
    let u;
    try { u = new URL(url); } catch { return url; }
    return hosts.has(u.hostname) ? baseOrigin + u.pathname + u.search : url;
  };
  const fromBase = (url) => (baseOrigin && (url === baseOrigin || url.startsWith(`${baseOrigin}/`) || url.startsWith(`${baseOrigin}?`)) ? `https://${domain}${url.slice(baseOrigin.length) || '/'}` : url);
  return { hosts, baseOrigin, toBase, fromBase };
}

/** A sitemap's <loc> URLs, split into pages and child sitemaps (for a sitemap index). */
export function sitemapLocs(xml) {
  const locs = [...String(xml ?? '').matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)].map((m) => m[1].replace(/&amp;/g, '&'));
  return /<sitemapindex[\s>]/i.test(xml) ? { pages: [], sitemaps: locs } : { pages: locs, sitemaps: [] };
}

/** Up to n items spread evenly through a list, first and last included. */
export function spread(items, n) {
  if (items.length <= n) return items;
  return Array.from({ length: n }, (_, i) => items[Math.round((i * (items.length - 1)) / (n - 1))]);
}

/** Run fn over items with at most `limit` in flight, so the audit doesn't hammer a site. */
export async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) { const i = next++; out[i] = await fn(items[i], i); }
  }));
  return out;
}

/**
 * What came back wrong in an echoed path (P5), or null when the answer doesn't echo it.
 * The probe path carries the marker, then CR LF, an HTML tag and a long run of one letter.
 * A tag is harmless in text/plain with nosniff, so it counts only in any other content type.
 */
export function echoProblems(text, marker, longRun, contentType = '') {
  const at = text.indexOf(marker);
  if (at < 0) return null; // no echo
  const problems = [];
  const after = text.slice(at + marker.length, at + marker.length + longRun.length + 200);
  if (/<b>/i.test(after) && !/^text\/plain/i.test(contentType)) problems.push(`an HTML tag from the path came back unescaped in ${contentType.split(';')[0] || 'an untyped answer'}`);
  if (/^[\r\n]/.test(after) || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(after.split('\n')[0])) problems.push('line breaks or control characters from the path came back');
  if (/[^\x20-\x7e\r\n]/.test(after.split('\n')[0])) problems.push('non-ASCII characters from the path came back');
  if (text.includes(longRun)) problems.push(`a ${longRun.length}-character path came back without a length cap`);
  return problems;
}

const SYMBOLS = { '✓': 'pass', '✗': 'fail', '!': 'warn', '–': 'skip' };

/**
 * One domain's results from a previous run: a status page (the --matrix output) or a --json
 * report. Returns { date, results: Map(id -> { status, level }) }, or null when the domain isn't in it.
 */
export function parsePrevious(text, domain) {
  const trimmed = String(text ?? '').trim();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    let data;
    try { data = JSON.parse(trimmed); } catch { return null; }
    const rep = [].concat(data).find((r) => r?.domain === domain);
    if (!rep || !Array.isArray(rep.results)) return null;
    return { date: String(rep.checked_at ?? '').slice(0, 10) || null, results: new Map(rep.results.map((r) => [r.id, { status: r.status, level: r.level }])) };
  }
  const lines = trimmed.split('\n');
  const header = lines.find((l) => /^\| ID \| Check \| Level \|/.test(l));
  if (!header) return null;
  const cols = header.split('|').slice(1, -1).map((c) => c.trim());
  const col = cols.indexOf(domain);
  if (col < 3) return null;
  const results = new Map();
  for (const line of lines) {
    const cells = line.split('|').slice(1, -1).map((c) => c.trim());
    if (cells.length !== cols.length || !/^[A-Z]\d+$/.test(cells[0])) continue;
    const status = SYMBOLS[cells[col]];
    if (status) results.set(cells[0], { status, level: cells[2] });
  }
  return { date: trimmed.match(/^Generated (\d{4}-\d{2}-\d{2})/m)?.[1] ?? null, results };
}

/** What changed between a previous run's results and this run's, as lists of labeled IDs. */
export function compareResults(previous, results) {
  const rank = { fail: 0, warn: 1, pass: 2 };
  const out = { better: [], worse: [], newlyChecked: [], noLongerChecked: [], levelChanged: [] };
  for (const r of results) {
    const p = previous.get(r.id);
    const was = p && p.status !== 'skip' ? p.status : null;
    const now = r.status !== 'skip' ? r.status : null;
    if (p && p.level && p.level !== r.level) out.levelChanged.push(`${r.id} (${p.level} to ${r.level})`);
    if (!was && now) out.newlyChecked.push(`${r.id} (${r.level}, ${now})`);
    else if (was && !now) out.noLongerChecked.push(r.id);
    else if (was && now && was !== now) (rank[now] > rank[was] ? out.better : out.worse).push(`${r.id} (${was} to ${now})`);
  }
  const current = new Set(results.map((r) => r.id));
  for (const [id, p] of previous) if (!current.has(id) && p.status !== 'skip') out.noLongerChecked.push(id);
  return out;
}

/** The comparison as printable lines. */
export function formatComparison(cmp, since) {
  const rows = [['Better', cmp.better], ['Worse', cmp.worse], ['Newly checked', cmp.newlyChecked], ['No longer checked', cmp.noLongerChecked], ['Level changed', cmp.levelChanged]]
    .filter(([, ids]) => ids.length);
  if (!rows.length) return [`Since ${since}: no changes.`];
  return [`Since ${since}:`, ...rows.map(([label, ids]) => `  ${label}: ${ids.join(', ')}`)];
}
