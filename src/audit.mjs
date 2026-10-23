// security-pranks-audit: check that a site answers secret-hunting probes safely, against the
// Agent Security Pranks Standard.
//
// Library entry. The command-line tool is bin/security-pranks-audit.mjs.
// The standard and what each ID means: STANDARD.md in
// https://github.com/geeks-accelerator/agent-security-pranks
// Requests only the site you name (and its www or bare twin): GETs, a HEAD, and an empty POST and
// PUT to / that create nothing. It never follows a redirect off the site. Node 22, 24 or 26 at its security release, no dependencies.

import { request, TIMEOUT_MS } from './http.mjs';
import { PROBES, FRAMEWORK_ENDPOINTS, isSecretProbe, credentialShapes, withoutPath, baseMapper, sitemapLocs, spread, mapLimit, echoProblems, edgeBlock, secretAssignments, cacheProblem, instructsAgent, securityTxtProblem, SCANNER_TAG, agentHeaders } from './helpers.mjs';

export const VERSION = '1.1.3';
export const REPO = 'https://github.com/geeks-accelerator/agent-security-pranks';
const UA = `security-pranks-audit/${VERSION} (+${REPO})`;
export const LEVELS = ['required', 'recommended'];
const ORDER = ['P1', 'P2', 'P3', 'P4', 'P5', 'P6', 'P8', 'H1', 'H2', 'X1', 'C1', 'C2'];
const PAGES = 10; // sitemap pages read for P6
const LIMIT = 4; // requests in flight to one site

// Items the scorecard can't see from outside. Each project checks these in review and tests.
export const REVIEW = [
  ['H3', 'the runtime (Node, Python, PHP) is pinned and on its current security release'],
  ['P6', 'the probe pattern matches none of your real routes: run it over every route in a test (the scorecard reads a sample of the sitemap)'],
  ['P7', 'any fact the prank states appears word for word in the published source, checked by a test'],
  ['X2', 'no canary tokens dressed up as a prank'],
  ['C3', 'the 404 page has a line for people, in the product\'s voice, pointing somewhere useful'],
  ['C4', 'a public page of misses, if you have one: paths and counts only, never addresses, and every path cleaned before it goes on the page'],
  ['T1', 'each check runs against the built server and was seen failing once with the feature off'],
  ['T2', 'a day of logs read before and after (security-pranks-audit --logs)'],
];

/** Two or more KEY=value lines: the shape of an env-file prank. */
export const looksLikePrank = (text) => (String(text ?? '').match(/^\s*(?:export\s+)?[A-Z][A-Z0-9_]*\s*=/gm) ?? []).length >= 2;

export async function audit(domain, { base = null, timeoutMs = TIMEOUT_MS } = {}) {
  const rand = Math.random().toString(36).slice(2, 10);
  const { hosts, baseOrigin, toBase, fromBase, hostFor } = baseMapper(domain, base);
  const onSite = (url) => { try { return hosts.has(new URL(url).hostname); } catch { return false; } };

  // One request in the domain's terms. Only the site's own hosts are ever requested.
  async function get(url, { method = 'GET', body, follow = false } = {}) {
    for (let hop = 0; ; hop++) {
      if (!onSite(url)) return { status: 0, headers: new Headers(), text: '', ms: 0, url, type: '', error: 'refused: not this site' };
      const target = toBase(url);
      // With --base on a local build, the request names the domain as its Host, so a server
      // that picks its site by Host serves the site being scored rather than its default.
      const host = hostFor(url);
      const headers = host ? { host } : {};
      const res = await request(target, { method, body, headers, userAgent: UA, timeoutMs });
      const loc = res.headers.get('location');
      const next = loc ? fromBase(new URL(loc, target).href) : null;
      if (follow && res.status >= 300 && res.status < 400 && next && onSite(next) && hop < 5) { url = next; continue; }
      return { ...res, url, location: next, type: res.headers.get('content-type') ?? '' };
    }
  }
  const path = (url) => { const u = new URL(url); return u.pathname + u.search; };
  const ok = (r) => r.status >= 200 && r.status < 300;
  const ct = (r) => r.type.split(';')[0].trim() || 'no content type';

  const results = [];
  const record = (id, name, level, status, detail) => results.push({ id, name, level, status, detail });
  const pass = (id, name, level, detail) => record(id, name, level, 'pass', detail);
  const miss = (id, name, level, detail) => record(id, name, level, level === 'required' ? 'fail' : 'warn', detail);
  const wrong = (id, name, level, detail) => record(id, name, level, 'fail', detail); // present but unsafe
  const warn = (id, name, level, detail) => record(id, name, level, 'warn', detail);
  const skip = (id, name, level, detail) => record(id, name, level, 'skip', detail);
  const finish = (extra) => {
    results.sort((a, b) => LEVELS.indexOf(a.level) - LEVELS.indexOf(b.level) || ORDER.indexOf(a.id) - ORDER.indexOf(b.id));
    return { domain, base: baseOrigin, version: VERSION, checked_at: new Date().toISOString(), ...extra, results };
  };

  // The site's own origin: follow the homepage's redirects between the domain and its www twin,
  // and from http to https, so the probes go where the site lives and a host redirect isn't
  // mistaken for an answer to a probe.
  const home = await get(`https://${domain}/`, { follow: true });
  const origin = home.status ? new URL(home.url).origin : `https://${domain}`;
  if (!home.status) {
    wrong('P1', 'Probes answer with a failure', 'required', `no answer from ${origin}: ${home.error}`);
    return finish({ origin, prank: false, framework: null });
  }
  // A domain that only redirects to another site (an alias, an old name) has nothing of its own
  // to score: its probes go wherever its redirect goes.
  if (home.status >= 300 && home.status < 400 && home.location && !onSite(home.location)) {
    skip('P1', 'Probes answer with a failure', 'required', `${origin}/ redirects to ${new URL(home.location).host}: a redirect-only domain is out of scope, so audit that site instead`);
    return finish({ origin, prank: false, framework: null, redirects_to: new URL(home.location).host });
  }
  // A CDN that blocks the audit's own requests hides the site; say so instead of scoring the block page.
  if (edgeBlock(home)) {
    warn('P1', 'Probes answer with a failure', 'required', `${edgeBlock(home)} blocked the audit at ${origin}/ (${home.status}), so nothing reached the site. Allow the user agent security-pranks-audit in the CDN's rules, or score a build with --base`);
    return finish({ origin, prank: false, framework: null, blocked_by: edgeBlock(home) });
  }

  const marker = `spa${rand}`;
  const longRun = 'z'.repeat(600);
  const echoPath = `/.env.${marker}%0d%0a%3Cb%3E${longRun}`;
  const missingPath = `/no-such-page-${rand}`;
  const framework = FRAMEWORK_ENDPOINTS.find((f) => f.detect(home)) ?? null;

  const [missing, head, post, put, fw, robots, sitemap, ...probes] = await mapLimit([
    () => get(origin + missingPath),
    () => get(`${origin}/`, { method: 'HEAD' }),
    () => get(`${origin}/`, { method: 'POST', body: '' }),
    () => get(`${origin}/`, { method: 'PUT', body: '' }),
    () => (framework && !framework.used(home) ? get(origin + framework.path) : null),
    () => get(`${origin}/robots.txt`, { follow: true }),
    () => get(`${origin}/sitemap.xml`, { follow: true }),
    ...[...PROBES, echoPath].map((p) => () => get(origin + p)),
  ], LIMIT, (job) => job());
  const probeRows = probes.map((r, i) => ({ path: [...PROBES, echoPath][i], r }));
  const shown = (p) => (p === echoPath ? '/.env.<echo test>' : p);

  // Which probes got a prank: an answer that isn't the site's ordinary 404 page, or one shaped like
  // an env file. A CDN or firewall block page is neither: the request never reached the site.
  const missingNorm = withoutPath(missing.text, missingPath);
  // An API's own error (JSON, or an auth or rate-limit status) is the API answering, not a prank:
  // sites with an API under /api answer /API/.ENV that way, and that's fine.
  const blocked = probeRows.filter(({ r }) => edgeBlock(r));
  const apiAnswer = (r) => !looksLikePrank(r.text) && (/json/i.test(r.type) || [401, 403, 405, 429].includes(r.status));
  const byApi = probeRows.filter(({ r }) => !edgeBlock(r) && r.status >= 400 && r.status < 500 && apiAnswer(r));
  const isPrank = ({ path: p, r }) => r.status >= 400 && r.status < 500 && r.text.trim() !== '' && !edgeBlock(r) && !apiAnswer(r)
    && (withoutPath(r.text, p) !== missingNorm || looksLikePrank(r.text));
  const pranked = probeRows.filter(isPrank);
  const prankBodies = new Set(pranked.map(({ path: p, r }) => withoutPath(r.text, p)));
  const prank = pranked.length > 0;
  // The prank should point real researchers to security.txt (C2); if it does, the file must work.
  const linksSecurityTxt = pranked.some(({ r }) => /security\.txt/i.test(r.text));
  const securityTxt = linksSecurityTxt ? await get(`${origin}/.well-known/security.txt`, { follow: true }) : null;

  // The sitemap's pages: robots.txt's Sitemap lines, else /sitemap.xml, one index level deep.
  const sitemapUrls = ok(robots) ? [...robots.text.matchAll(/^\s*sitemap:\s*(\S+)/gim)].map((m) => m[1]) : [];
  const maps = sitemapUrls.length ? await mapLimit(sitemapUrls.slice(0, 3), LIMIT, (u) => get(u, { follow: true })) : [sitemap];
  let pageUrls = [];
  for (const m of maps.filter(ok)) {
    const { pages, sitemaps } = sitemapLocs(m.text);
    pageUrls.push(...pages);
    if (sitemaps.length) for (const child of (await mapLimit(sitemaps.slice(0, 5), LIMIT, (u) => get(u, { follow: true }))).filter(ok)) pageUrls.push(...sitemapLocs(child.text).pages);
  }
  pageUrls = [...new Set(pageUrls)];
  const sitePages = pageUrls.filter(onSite);
  // A sample of the sitemap's pages, read once: P6 checks none gets the prank, H2 looks for the framework endpoint in use.
  const sample = sitePages.length ? spread(sitePages, PAGES) : [`${origin}/`];
  const pages = sitePages.length ? await mapLimit(sample, LIMIT, (u) => get(u, { follow: true })) : [home];

  // ---- P1 probes answer with a failure (required) ----
  {
    const id = 'P1', name = 'Probes answer with a failure', level = 'required';
    const found = probeRows.filter(({ r }) => ok(r)).map(({ path: p, r }) => `${shown(p)} (${r.status})`);
    const crashed = probeRows.filter(({ r }) => r.status >= 500).map(({ path: p, r }) => `${shown(p)} (${r.status})`);
    const silent = probeRows.filter(({ r }) => r.status === 0).map(({ path: p, r }) => `${shown(p)} (${r.error})`);
    const moved = probeRows.filter(({ r }) => r.status >= 300 && r.status < 400).map(({ path: p, r }) => `${shown(p)} (${r.status} to ${r.location ? path(r.location) : 'nowhere'})`);
    const statuses = Object.entries(probeRows.reduce((a, { r }) => ({ ...a, [r.status]: (a[r.status] ?? 0) + 1 }), {})).map(([s, n]) => `${s} ×${n}`).join(', ');
    if (found.length) wrong(id, name, level, `success on ${found.join(', ')}: scanners score by status code, so a 2xx marks the site as "found something" on shared target lists, even a static site with nothing to leak. Serve the joke with a 404`);
    else if (crashed.length) wrong(id, name, level, `server errors on ${crashed.join(', ')}: the probe reached code that crashed; answer it before the framework does`);
    else if (silent.length) wrong(id, name, level, `no answer on ${silent.join(', ')}`);
    else if (moved.length) warn(id, name, level, `redirects on ${moved.join(', ')}: scanners follow them and score the target; answer the probe itself with a 4xx`);
    else pass(id, name, level, `${probeRows.length} of ${probeRows.length} probes answered with a 4xx (${statuses})`);
  }

  // ---- P2 nothing shaped like a credential (required) ----
  {
    const id = 'P2', name = 'Nothing shaped like a credential', level = 'required';
    const answers = [...probeRows, { path: missingPath, r: missing }];
    const bad = answers.map(({ path: p, r }) => [p, credentialShapes(r.text)]).filter(([, k]) => k.length);
    const named = [...new Set(answers.flatMap(({ r }) => secretAssignments(r.text)))];
    if (bad.length) wrong(id, name, level, bad.map(([p, k]) => `${shown(p)}: ${k.join(', ')}`).join('; ') + '. A secret scanner would extract it, and someone else chases a false alarm');
    else if (named.length) warn(id, name, level, `${named.join(', ')} ${named.length === 1 ? 'is' : 'are'} given a one-word value. A person reads it as a joke; a generic secret scanner keys on the name and extracts the value. Use a setting (PASSWORD_REQUIRED=false), a quoted phrase, or a name that isn't secret-shaped`);
    else pass(id, name, level, `no credential-shaped strings in ${answers.length} answers`);
  }

  // ---- P3 never cached or indexed (required) ----
  {
    const id = 'P3', name = 'Not indexed, not cached for long', level = 'required';
    const inSitemap = pageUrls.filter((u) => { try { return isSecretProbe(new URL(u).pathname); } catch { return false; } }).map(path);
    const group = (rows, test) => {
      const by = new Map(); // problem -> paths
      for (const { path: p, r } of rows) { const what = test(r); if (what) by.set(what, [...(by.get(what) ?? []), shown(p)]); }
      return [...by].map(([what, paths]) => `${paths.length} prank answer${paths.length === 1 ? '' : 's'} (${paths.slice(0, 2).join(', ')}${paths.length > 2 ? '...' : ''}): ${what}`);
    };
    const fails = group(pranked, (r) => (/noindex/i.test(r.headers.get('x-robots-tag') ?? '') ? null : 'no X-Robots-Tag: noindex'));
    if (inSitemap.length) fails.unshift(`the sitemap lists ${inSitemap.slice(0, 3).join(', ')}${inSitemap.length > 3 ? ` and ${inSitemap.length - 3} more` : ''}`);
    const warns = group(pranked, (r) => cacheProblem(r.headers.get('cache-control')));
    if (fails.length) wrong(id, name, level, `${fails.concat(warns).join('; ')}. Search shows an indexed prank to people looking for the site`);
    else if (!prank) skip(id, name, level, 'no prank found (C1), and the sitemap lists no probe paths');
    else if (warns.length) warn(id, name, level, `${warns.join('; ')}. An old prank keeps answering after you change it`);
    else pass(id, name, level, `${pranked.length} prank answers send noindex and no-store or a cache of a day or less; the sitemap lists no probe paths`);
  }

  // ---- P4 plain text, not sniffed (required) ----
  {
    const id = 'P4', name = 'Plain text, not sniffed', level = 'required';
    const problems = pranked.map(({ path: p, r }) => {
      const lacks = [];
      if (!/^text\/plain/i.test(r.type)) lacks.push(`is ${ct(r)}`);
      if (!/nosniff/i.test(r.headers.get('x-content-type-options') ?? '')) lacks.push('lacks X-Content-Type-Options: nosniff');
      return lacks.length ? `${shown(p)} ${lacks.join(' and ')}` : null;
    }).filter(Boolean);
    if (!prank) skip(id, name, level, 'no prank found (C1)');
    else if (problems.length) wrong(id, name, level, `${problems.slice(0, 4).join('; ')}: a browser could render the scanner-controlled parts as a page`);
    else pass(id, name, level, `${pranked.length} prank answers are text/plain with nosniff`);
  }

  // ---- P5 an echoed path is cleaned (required, where the prank echoes the path) ----
  {
    const id = 'P5', name = 'Echoed path cleaned', level = 'required';
    const echo = probes[probes.length - 1];
    const problems = echo.status >= 400 && echo.status < 500 ? echoProblems(echo.text, marker, longRun, echo.type) : null;
    if (!problems) skip(id, name, level, 'the prank doesn\'t echo the requested path');
    else if (problems.length) wrong(id, name, level, `${problems.join('; ')}: the scanner controls the path, so strip it to printable ASCII and cap its length`);
    else pass(id, name, level, 'the echoed path comes back as printable ASCII with a length cap');
  }

  // ---- P6 real pages never get the prank (required) ----
  {
    const id = 'P6', name = 'Real pages never get the prank', level = 'required';
    const hit = pages.map((r, i) => [sample[i], r]).filter(([u, r]) => prankBodies.has(withoutPath(r.text, path(u))) || (!ok(r) && looksLikePrank(r.text))).map(([u, r]) => `${path(u)} (${r.status})`);
    const caught = sitePages.map(path).filter((p) => isSecretProbe(p.split('?')[0]));
    const read = sitePages.length ? `${pages.length} of ${sitePages.length} sitemap pages` : 'the homepage (no sitemap found)';
    if (hit.length) wrong(id, name, level, `${hit.join(', ')} answered with the prank: the pattern catches real pages`);
    else if (caught.length) warn(id, name, level, `the playbook's pattern would catch ${caught.slice(0, 3).join(', ')}${caught.length > 3 ? ` and ${caught.length - 3} more` : ''}; if you use it, narrow it (read ${read}, none answered with the prank)`);
    else pass(id, name, level, `read ${read}: none answered with the prank`);
  }

  // ---- P8 ordinary 404s stay ordinary (required) ----
  {
    const id = 'P8', name = 'Ordinary 404s stay ordinary', level = 'required';
    const leaked = prankBodies.has(missingNorm) || looksLikePrank(missing.text);
    if (leaked) wrong(id, name, level, `${missingPath.replace(rand, '<random>')} answered with the prank: a reader who mistypes a URL sees the joke`);
    else if (!missing.status) wrong(id, name, level, `no answer for a missing page: ${missing.error}`);
    else pass(id, name, level, `a missing page answers ${missing.status} ${ct(missing)} with the site's own page${ok(missing) ? ' (a 200 for a missing page is a soft 404; search engines prefer a real 404)' : ''}`);
  }

  // ---- H1 refuse methods the site doesn't use (required) ----
  {
    const id = 'H1', name = 'Unused methods refused', level = 'required';
    // A homepage behind a login (401) still shows the guard: it answered. Any other failure refuses reads.
    const readable = (r) => (r.status >= 200 && r.status < 400) || r.status === 401;
    const allow = (post.headers.get('allow') ?? '').toUpperCase();
    const refused = (r) => r.status >= 400 && r.status < 500;
    const accepted = [['POST', post], ['PUT', put]].filter(([, r]) => r.status >= 200 && r.status < 400);
    const both = `POST / answers ${post.status}, PUT / answers ${put.status}`;
    if (!readable(home)) wrong(id, name, level, `GET / answers ${home.status}: a guard refuses reads`);
    else if (!readable(head)) wrong(id, name, level, `HEAD / answers ${head.status || head.error}: a guard refuses reads`);
    else if (post.status >= 500 || put.status >= 500) wrong(id, name, level, `${[['POST', post], ['PUT', put]].filter(([, r]) => r.status >= 500).map(([m, r]) => `${m} / answers ${r.status}`).join(', ')}: a framework error, and the request reached code; refuse methods a route doesn't use, with 405`);
    else if (post.status === 405 && !allow) warn(id, name, level, 'POST / answers 405 without an Allow header (RFC 9110 requires one): send Allow with the methods / takes, such as GET, HEAD');
    else if (accepted.length) warn(id, name, level, `${accepted.map(([m, r]) => `${m} / answers ${r.status}`).join(', ')}: the homepage accepts ${accepted.map(([m]) => m).join(' and ')}. If nothing on / takes it, answer 405 with Allow: GET, HEAD`);
    else if (refused(post) && refused(put)) pass(id, name, level, post.status === 405 ? `${both}, Allow: ${allow}` : `${both}: refused`);
    else warn(id, name, level, `${both}${post.error ? ` (${post.error})` : ''}`);
  }

  // ---- H2 unused framework endpoints refused (required, where the framework has one) ----
  {
    const id = 'H2', name = 'Unused framework endpoints refused', level = 'required';
    // A page that uses the endpoint means it's in use. The audit reads a sample, so it fails only
    // when the sample is the whole sitemap; otherwise an unseen page might use it, and it warns.
    const usedOn = framework ? sample.filter((u, i) => framework.used(pages[i])).map(path) : [];
    const wholeSite = sitePages.length > 0 && sitePages.length <= pages.length;
    if (!framework) skip(id, name, level, `no framework with a known always-on endpoint found (checked ${FRAMEWORK_ENDPOINTS.map((f) => f.framework).join(', ')})`);
    else if (!fw) skip(id, name, level, `${framework.framework}: the homepage uses ${framework.label}, so it's in use; keep the framework patched (H3)`);
    else if (usedOn.length) skip(id, name, level, `${framework.framework}: ${usedOn[0]} uses ${framework.label}, so it's in use; keep the framework patched (H3)`);
    else if (fw.status === 404) pass(id, name, level, `${framework.framework}: ${framework.label} answers 404`);
    else if (wholeSite) wrong(id, name, level, `${framework.framework}: ${framework.label} answers ${fw.status || fw.error}, and none of the site's ${sitePages.length} sitemap pages uses it. Answer 404, so the next advisory in that endpoint can't reach you`);
    else warn(id, name, level, `${framework.framework}: ${framework.label} answers ${fw.status || fw.error}, and none of the ${pages.length} pages read uses it${sitePages.length ? ` (of ${sitePages.length} in the sitemap)` : ''}. If no page uses it, answer 404 so the next advisory in that endpoint can't reach you; if one does, keep the framework patched`);
  }

  // ---- X1 no retaliation (required) ----
  {
    const id = 'X1', name = 'No retaliation', level = 'required';
    const rows = [...probeRows, { path: missingPath, r: missing }];
    const problems = [];
    for (const { path: p, r } of rows) {
      if (r.tooBig) problems.push(`${shown(p)}: ${r.error}`);
      else if (r.slow) problems.push(`${shown(p)}: ${r.error}`);
      else if (r.status === 0 && /no answer/.test(r.error ?? '')) problems.push(`${shown(p)}: ${r.error} (a tarpit holds the connection)`);
      else if (r.status >= 300 && r.status < 400 && r.location && !onSite(r.location)) problems.push(`${shown(p)}: redirects to ${new URL(r.location).host}`);
    }
    const slowest = Math.max(...rows.map(({ r }) => r.ms ?? 0));
    const largest = Math.max(...rows.map(({ r }) => Buffer.byteLength(r.text ?? '')));
    if (problems.length) wrong(id, name, level, `${problems.join('; ')}. Anything that costs the visitor, or points bots at someone else, stops being a prank`);
    else pass(id, name, level, `every answer within ${(slowest / 1000).toFixed(1)} seconds, the largest ${(largest / 1024).toFixed(1)} KB, no redirects off the site`);
  }

  // ---- C1 a prank answers the probes (recommended) ----
  {
    const id = 'C1', name = 'A prank answers the probes', level = 'recommended';
    const counted = probeRows.filter((x) => x.path !== echoPath && !edgeBlock(x.r) && !byApi.includes(x));
    const plain = counted.filter((x) => !isPrank(x)).map(({ path: p, r }) => `${shown(p)} (${r.status} ${ct(r)})`);
    const got = counted.length - plain.length;
    const edge = blocked.length ? `; ${blocked.map(({ path: p, r }) => `${shown(p)} blocked by ${edgeBlock(r)}`).join(', ')} before it reached the site` : '';
    const kinds = new Set(pranked.filter((x) => x.path !== echoPath).map(({ path: p, r }) => withoutPath(r.text, p))).size;
    const api = byApi.filter((x) => x.path !== echoPath).map(({ path: p, r }) => `${shown(p)} (${r.status} ${ct(r)})`);
    const edgeAndApi = edge + (api.length ? `; ${api.join(', ')} answered by the site's API` : '');
    const tagged = pranked.some(({ r }) => SCANNER_TAG.test(r.text)) ? ', with a tagged link to count follow-through' : '';
    if (!prank) miss(id, name, level, `the probes get the site's ordinary 404 page${edgeAndApi}. That's safe; a prank is optional (see the menu)`);
    else if (plain.length) warn(id, name, level, `${got} of ${counted.length} probes that reached the site get a prank; no prank on ${plain.join(', ')}${edgeAndApi}`);
    else pass(id, name, level, `${got} of ${counted.length} probes that reached the site get a prank (${pranked[0].r.status} ${ct(pranked[0].r)}${kinds > 1 ? `, ${kinds} different replies` : ''}${tagged})${edgeAndApi}`);
  }

  // ---- C2 a note for AI agents (recommended) ----
  {
    const id = 'C2', name = 'A note for AI agents', level = 'recommended';
    const headerNotes = [...new Map(pranked.flatMap(({ r }) => agentHeaders(r.headers))).entries()];
    const orders = [...new Set(pranked.flatMap(({ r }) => [r.text, ...agentHeaders(r.headers).map(([, v]) => v)]).flatMap(instructsAgent))];
    const door = securityTxt ? securityTxtProblem(securityTxt) : null;
    const problems = [];
    if (orders.length) problems.push(`the prank gives the agent ${orders.join(' and ')}. That works only on an agent that obeys instructions it finds in a response, against its operator's task. Invite the operator instead, with a link`);
    if (door) problems.push(`the prank points to /.well-known/security.txt, which ${door}: a real researcher who follows it finds no way to report`);
    const inBody = pranked.some(({ r }) => /\b(ai agents?|agents?|artificial minds?|llms?|language models?)\b/i.test(r.text));
    const noted = inBody || headerNotes.length > 0;
    const where = [inBody ? 'the body' : null, headerNotes.length ? `a header (${headerNotes.map(([n]) => n).join(', ')})` : null].filter(Boolean).join(' and ');
    const tail = linksSecurityTxt ? ', and points real researchers to a working security.txt' : '. Add a link to /.well-known/security.txt, so a real researcher has a way to report';
    if (!prank) skip(id, name, level, 'no prank found (C1)');
    else if (problems.length) warn(id, name, level, problems.join('; '));
    else if (noted) pass(id, name, level, `the prank has a note addressed to AI agents in ${where}, gives them no orders${tail}`);
    else miss(id, name, level, 'the prank has no note for AI agents. Some scanners are driven by language models that read the answer');
  }

  return finish({ origin, prank, framework: framework?.framework ?? null });
}

export function score(results, level) {
  const rows = results.filter((r) => r.level === level && r.status !== 'skip');
  return rows.length ? `${rows.filter((r) => r.status === 'pass').length} of ${rows.length}` : 'n/a';
}

// Markdown status page for several sites, for a project's docs/security-pranks-status.md.
export function matrix(reports, command) {
  const sym = { pass: '✓', warn: '!', fail: '✗', skip: '–' };
  const domains = reports.map((r) => r.domain);
  const seen = new Map();
  for (const rep of reports) for (const r of rep.results) if (!seen.has(r.id)) seen.set(r.id, [r.id, r.name, r.level]);
  const ids = [...seen.values()].sort((a, b) => LEVELS.indexOf(a[2]) - LEVELS.indexOf(b[2]) || ORDER.indexOf(a[0]) - ORDER.indexOf(b[0]));
  const out = [
    '# Agent Security Pranks Status', '',
    `Generated ${new Date().toISOString().slice(0, 10)} by \`${command}\` (security-pranks-audit v${VERSION}). Don't edit it by hand: regenerate it. What each ID means: [the standard](${REPO}/blob/main/STANDARD.md).`, '',
    'The scorecard sees only what is visible from outside a site. Items checked in review and tests (listed at the end) aren\'t in these numbers.', '',
    '✓ pass, ✗ fail, ! warning, – not applicable.', '',
    `| ID | Check | Level | ${domains.join(' | ')} |`, `|---|---|---|${domains.map(() => '---').join('|')}|`,
    ...ids.map(([id, name, level]) => `| ${id} | ${name} | ${level} | ${reports.map((rep) => sym[rep.results.find((r) => r.id === id)?.status ?? 'skip']).join(' | ')} |`),
    `| | **Required passed** | | ${reports.map((rep) => `**${score(rep.results, 'required')}**`).join(' | ')} |`,
    `| | Recommended passed | | ${reports.map((rep) => score(rep.results, 'recommended')).join(' | ')} |`,
    `| | Prank found | | ${reports.map((rep) => (rep.redirects_to ? `redirects to ${rep.redirects_to}` : rep.blocked_by ? `audit blocked by ${rep.blocked_by}` : rep.prank ? 'yes' : 'no')).join(' | ')} |`,
    `| | Framework | | ${reports.map((rep) => rep.framework ?? 'not detected').join(' | ')} |`,
    '',
    '## What to fix, per site', '',
    'Failures and warnings with the scorecard\'s reason, required items first.', '',
  ];
  for (const rep of reports) {
    out.push(`### ${rep.domain}`, '');
    const open = rep.results.filter((r) => r.status === 'fail' || r.status === 'warn');
    if (!open.length) out.push('Everything the scorecard can see passes.');
    for (const r of open) out.push(`- **${r.id}** ${r.name} (${r.status === 'fail' ? 'fail' : 'warning'}, ${r.level}): ${r.detail}`);
    out.push('');
  }
  out.push('## Checked in review and tests, not scored', '', ...REVIEW.map(([id, what]) => `- **${id}**: ${what}`), '');
  return out.join('\n');
}
