// End to end: audit() against two fixture sites on localhost, through --base, with no outside network.
// Every scored check passes on the good site and fails (or warns, for recommended items) on the broken one:
// the playbook's "a check that has never failed has not been tested", built into CI.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { audit, matrix } from '../src/audit.mjs';
import { compareResults, parsePrevious } from '../src/helpers.mjs';
import { logTally } from '../src/logs.mjs';
import { startFixture } from './fixture-site.mjs';

const run = async (kind) => {
  const site = await startFixture({ kind });
  try { return { rep: await audit(site.domain, { base: site.base, timeoutMs: 1500 }), log: site.log }; }
  finally { await site.close(); }
};
const byId = (rep) => Object.fromEntries(rep.results.map((r) => [r.id, r]));

test('the good fixture passes every scored check', async () => {
  const { rep, log } = await run('good');
  const by = byId(rep);
  for (const r of rep.results) assert.equal(r.status, 'pass', `${r.id}: ${r.detail}`);
  for (const id of ['P1', 'P2', 'P3', 'P4', 'P5', 'P6', 'P8', 'H1', 'H2', 'X1', 'C1', 'C2']) assert.ok(by[id], `${id} ran`);
  assert.equal(rep.prank, true);
  assert.equal(rep.framework, 'Next.js');
  assert.match(by.P6.detail, /read 4 of 4 sitemap pages/);
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
  assert.match(by.X1.detail, /\/\.git\/config: body still arriving/);
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
