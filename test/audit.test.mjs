// End to end: audit() against two fixture sites on localhost, through --base, with no outside network.
// Every scored check passes on the good site and fails (or warns, for recommended items) on the broken one:
// the playbook's "a check that has never failed has not been tested", built into CI.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { audit, matrix } from '../src/audit.mjs';
import { compareResults, parsePrevious } from '../src/helpers.mjs';
import { logTally } from '../src/logs.mjs';
import { startFixture } from './fixture-site.mjs';
import { execFile } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';

const run = async (kind) => {
  const site = await startFixture({ kind });
  try { return { rep: await audit(site.domain, { base: site.base, timeoutMs: 1500 }), log: site.log, hosts: site.hosts }; }
  finally { await site.close(); }
};
const byId = (rep) => Object.fromEntries(rep.results.map((r) => [r.id, r]));

test('--base names the domain as the Host, so a server with several sites serves the right one', async () => {
  // The fixtures answer only for their own domain, like a server that runs several sites.
  // Before 1.1.3, --base sent Host: 127.0.0.1:<port>, and such a server scored whatever it
  // served by default, under the domain's name.
  const { rep, hosts } = await run('good');
  assert.deepEqual([...hosts].filter((h) => h !== 'good.example' && h !== 'www.good.example'), []);
  assert.equal(rep.prank, true);
});

test('the good fixture passes every scored check', async () => {
  const { rep, log } = await run('good');
  const by = byId(rep);
  for (const r of rep.results) assert.equal(r.status, 'pass', `${r.id}: ${r.detail}`);
  for (const id of ['P1', 'P2', 'P3', 'P4', 'P5', 'P6', 'P8', 'H1', 'H2', 'X1', 'C1', 'C2']) assert.ok(by[id], `${id} ran`);
  assert.equal(rep.prank, true);
  assert.equal(rep.framework, 'Next.js');
  assert.match(by.P6.detail, /read 4 of 4 sitemap pages/);
  assert.match(by.C2.detail, /points real researchers to a working security\.txt/);
  assert.match(by.C2.detail, /in the body and a header \(x-note-for-agents\)/);
  assert.match(by.C1.detail, /^7 of 7 probes that reached the site get a prank .*\/wp-config\.php blocked by Cloudflare/);

  // --logs reads what the audit just requested, and names it.
  const tally = logTally();
  log.forEach((l) => tally.add(l));
  const res = tally.result();
  const env = res.kinds.find((k) => k.kind === 'env files');
  assert.deepEqual(Object.keys(env.families), ['This audit (security-pranks-audit)']);
  assert.deepEqual(Object.keys(env.statuses), ['404']);
  assert.deepEqual(res.succeeded_or_crashed, []);
});

test('the broken fixture fails every required check, each for its planted reason', async () => {
  const { rep, log } = await run('broken');
  const by = byId(rep);
  for (const r of rep.results.filter((x) => x.level === 'required')) assert.equal(r.status, 'fail', `${r.id}: ${r.detail}`);
  assert.match(by.P1.detail, /success on \/\.env \(200\)/);
  assert.match(by.P2.detail, /\/\.env: AWS access key ID/);
  assert.match(by.P3.detail, /the sitemap lists \/\.env/);
  assert.match(by.P4.detail, /is text\/html/);
  assert.match(by.P5.detail, /line breaks or control characters/);
  assert.match(by.P5.detail, /without a length cap/);
  assert.match(by.P6.detail, /\/environment-report \(404\) answered with the prank/);
  assert.match(by.P8.detail, /answered with the prank/);
  assert.match(by.H1.detail, /POST \/ answers 500/);
  assert.match(by.H2.detail, /\/_next\/image answers 400/);
  assert.match(by.X1.detail, /\/wp-config\.php: body over 256 KB/);
  assert.match(by.X1.detail, /\/\.git\/config: body still arriving after 1\.5 seconds, twice in a row/);
  assert.match(by.X1.detail, /\/\.aws\/credentials: redirects to elsewhere\.example/);
  assert.equal(by.C2.status, 'warn');

  // --logs flags the 2xx probe and the 5xx POSTs, without addresses.
  const tally = logTally();
  log.forEach((l) => tally.add(l));
  const res = tally.result();
  assert.ok(res.succeeded_or_crashed.some((h) => h.request === '200 GET /.env'), JSON.stringify(res.succeeded_or_crashed));
  assert.ok(res.succeeded_or_crashed.some((h) => h.request === '500 POST /'));
  assert.doesNotMatch(JSON.stringify(res), /127\.0\.0\.1/);
});

test('an app with an API and a form, and no prank, passes every required check', async () => {
  const { rep } = await run('api');
  const by = byId(rep);
  for (const r of rep.results.filter((x) => x.level === 'required')) assert.notEqual(r.status, 'fail', `${r.id}: ${r.detail}`);
  assert.equal(rep.prank, false);
  assert.equal(rep.framework, null);
  assert.match(by.H1.detail, /POST \/ answers 404, PUT \/ answers 404: refused/);
  assert.match(by.C1.detail, /\/API\/\.ENV \(401 application\/json\) answered by the site's API/);
  for (const id of ['P3', 'P4', 'C2', 'H2']) assert.equal(by[id].status, 'skip', id);
});

// A 404 page with a request ID, and Express's default 404 that echoes the path: neither is a
// prank, and a site with no prank that's otherwise safe passes every required check.
for (const [kind, page] of [['stamped', 'a 404 page with a request ID'], ['express', "Express's default 404 page"]]) {
  test(`a site with no prank and ${page} passes every required check`, async () => {
    const { rep } = await run(kind);
    const by = byId(rep);
    for (const r of rep.results.filter((x) => x.level === 'required')) assert.notEqual(r.status, 'fail', `${r.id}: ${r.detail}`);
    assert.equal(rep.prank, false);
    for (const id of ['P3', 'P4', 'P5', 'C2']) assert.equal(by[id].status, 'skip', `${id}: ${by[id].detail}`);
    assert.equal(by.C1.status, 'warn');
  });
}

test('an ordinary 404 that echoes the path as unescaped HTML still fails P5, prank or not', async () => {
  const { rep } = await run('reflect');
  const by = byId(rep);
  assert.equal(rep.prank, false);
  assert.equal(by.P5.status, 'fail');
  assert.match(by.P5.detail, /an HTML tag from the path came back unescaped in text\/html/);
  assert.doesNotMatch(by.P5.detail, /length cap/);
});

test('a site whose ordinary 404 echoes a capped path, and has no prank, is not scored as having one', async () => {
  // Before 1.1.5 the echo test's answer, capped at 200 characters, didn't match the ordinary 404 once
  // the path was taken out, so a plain 404 was scored as a prank: P3 failed and C2 passed for it.
  const { rep } = await run('plain');
  const by = byId(rep);
  for (const r of rep.results.filter((x) => x.level === 'required')) assert.notEqual(r.status, 'fail', `${r.id}: ${r.detail}`);
  assert.equal(rep.prank, false);
  for (const id of ['P3', 'P4', 'P5', 'C2']) assert.equal(by[id].status, 'skip', `${id}: ${by[id].detail}`);
  assert.equal(by.C1.status, 'warn');
  // An ordinary 404 isn't the prank, so P5's prank rules skip it; the echo is clean anyway.
  assert.match(by.P5.detail, /ordinary 404/);
});

test('a playful first draft warns on secret-named keys, a long cache and orders to agents, and fails nothing', async () => {
  const { rep } = await run('cheeky');
  const by = byId(rep);
  assert.ok(!rep.results.some((r) => r.status === 'fail'), rep.results.filter((r) => r.status === 'fail').map((r) => r.id).join());
  assert.match(by.P2.detail, /SECRET_KEY, DATABASE_PASSWORD are given a one-word value/);
  assert.match(by.P3.detail, /cached for 168 hours/);
  assert.match(by.C2.detail, /gives the agent a request to send/);
  assert.match(by.C2.detail, /security\.txt, which answers 404/);
  assert.equal(by.P2.status, 'warn');
  assert.equal(by.P3.status, 'warn');
});

test('a static site gets no exception: a 200 on /.env fails P1, whatever its headers say', async () => {
  const { rep } = await run('static');
  const by = byId(rep);
  assert.equal(by.P1.status, 'fail');
  assert.match(by.P1.detail, /success on \/\.env \(200\).*even a static site with nothing to leak/);
  assert.equal(by.C1.status, 'warn'); // a 2xx is never graded as the prank
});

test('a probe that gets no answer once, then a 404, is retried: X1 passes', async () => {
  const { rep } = await run('flaky');
  const by = byId(rep);
  assert.equal(by.X1.status, 'pass', by.X1.detail);
});

test('an API-only domain with nothing at / passes H1: a 404 homepage is not a guard refusing reads', async () => {
  const { rep } = await run('apionly');
  const by = byId(rep);
  assert.equal(by.H1.status, 'pass', by.H1.detail);
  assert.match(by.H1.detail, /GET \/ answers 404 \(nothing to read at the homepage, which is fine\)/);
  for (const r of rep.results.filter((x) => x.level === 'required')) assert.notEqual(r.status, 'fail', `${r.id}: ${r.detail}`);
});

test('an alias domain and a CDN that blocks the audit are reported, not scored', async () => {
  const alias = (await run('alias')).rep;
  assert.equal(alias.redirects_to, 'elsewhere.example');
  assert.deepEqual(alias.results.map((r) => [r.id, r.status]), [['P1', 'skip']]);
  const blocked = (await run('blocked')).rep;
  assert.equal(blocked.blocked_by, 'Cloudflare');
  assert.deepEqual(blocked.results.map((r) => [r.id, r.status]), [['P1', 'warn']]);
  const md = matrix([alias, blocked], 'cmd');
  assert.match(md, /^\| \| Prank found \| \| redirects to elsewhere\.example \| audit blocked by Cloudflare \|$/m);
});

test('the status page covers both sites, and --compare finds a planted regression', async () => {
  const [good, bad] = await Promise.all([run('good'), run('broken')]);
  const md = matrix([good.rep, bad.rep], 'npx security-pranks-audit@1 --matrix good.example broken.example');
  assert.match(md, /^\| P1 \| Probes answer with a failure \| required \| ✓ \| ✗ \|$/m);
  assert.match(md, /\*\*Required passed\*\* \| \| \*\*10 of 10\*\* \| \*\*0 of 10\*\*/);
  assert.match(md, /^\| \| Prank found \| \| yes \| yes \|$/m);

  // Last month's page said good.example passed; this month it's the broken site's results.
  const previous = parsePrevious(md, 'good.example');
  const cmp = compareResults(previous.results, bad.rep.results);
  assert.ok(cmp.worse.includes('P1 (pass to fail)'), cmp.worse.join(', '));
  assert.ok(cmp.worse.includes('X1 (pass to fail)'));
});

test('the CLI reads a saved GraphQL Analytics response with --logs, and an access log as before', async () => {
  // Files built at run time: a pretty-printed analytics response (many lines, one document), a
  // response with only errors, and a one-line JSON access log that must still be read as a log.
  const dir = await mkdtemp(join(tmpdir(), 'spa-logs-'));
  const cli = (file, ...args) => promisify(execFile)(process.execPath, [new URL('../bin/security-pranks-audit.mjs', import.meta.url).pathname, '--logs', join(dir, file), ...args]).then((r) => ({ code: 0, ...r }), (e) => ({ code: e.code, stdout: e.stdout, stderr: e.stderr }));
  try {
    const rows = [[3560, '/.env', 404], [280, '/.git/config', 404], [900, '/about', 200]].map(([count, path, status]) => ({ count, dimensions: { clientRequestPath: path, edgeResponseStatus: status } }));
    await writeFile(join(dir, 'week.json'), JSON.stringify({ data: { viewer: { zones: [{ httpRequestsAdaptiveGroups: rows }] } }, errors: null }, null, 2));
    await writeFile(join(dir, 'denied.json'), JSON.stringify({ data: null, errors: [{ message: 'zone does not have access to the path' }] }));
    await writeFile(join(dir, 'one.jsonl'), '{"ClientRequestPath":"/.env","EdgeResponseStatus":404}\n');

    const week = await cli('week.json', '--json');
    assert.equal(week.code, 0, week.stderr);
    const rep = JSON.parse(week.stdout);
    assert.deepEqual([rep.source, rep.parsed, rep.probes], ['analytics groups', 4740, 3840]);
    assert.match((await cli('week.json')).stdout, /^Read 3 of 3 analytics rows/);

    const denied = await cli('denied.json');
    assert.equal(denied.code, 2);
    assert.match(denied.stderr, /errors and no rows: zone does not have access to the path/);

    const log = JSON.parse((await cli('one.jsonl', '--json')).stdout);
    assert.deepEqual([log.source, log.lines, log.probes], ['log lines', 1, 1]);
    assert.equal((await cli('one.jsonl')).code, 0, 'every probe got a 4xx');
    await writeFile(join(dir, 'hit.jsonl'), '{"ClientRequestPath":"/.env","EdgeResponseStatus":200}\n');
    assert.equal((await cli('hit.jsonl')).code, 1, 'a probe got a 2xx: exit 1, like the audit');
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('several domains without --matrix exit 2 and say so, instead of scoring only the first', async () => {
  const r = await promisify(execFile)(process.execPath, [new URL('../bin/security-pranks-audit.mjs', import.meta.url).pathname, 'a.example', 'b.example']).then(() => ({ code: 0 }), (e) => ({ code: e.code, stderr: e.stderr }));
  assert.equal(r.code, 2);
  assert.match(r.stderr, /2 domains given \(a\.example, b\.example\)\. To score them together on one status page, add --matrix/);
});
