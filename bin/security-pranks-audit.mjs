#!/usr/bin/env node
// security-pranks-audit: check that a site answers secret-hunting probes safely, against the
// Agent Security Pranks Standard.
//
//   security-pranks-audit <domain> [--json] [--compare previous] [--base url]
//   security-pranks-audit --matrix <domain> <domain> ...   (a markdown status page)
//   security-pranks-audit --logs <access-log> [--tag text ...] [--json]   (probe counts, before and after)
//
// Exits 1 when a required check fails, so it can gate a deploy.

import { readFileSync, createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { audit, matrix, score, LEVELS, REVIEW, VERSION } from '../src/audit.mjs';
import { parsePrevious, compareResults, formatComparison, mapLimit } from '../src/helpers.mjs';
import { logTally, formatLogs } from '../src/logs.mjs';

// engines in package.json only warns, so say it plainly before anything fails oddly.
// Each supported Node line at its current security release (the 2026-10-21 release fixed a
// Brotli decoder bug and TLS hostname bypasses in all three). TLS checks and the decoders are
// Node's, so the line matters less than being on its latest security release. End-of-life
// and odd-numbered lines get no security releases and are refused.
const NODE_LINES = { 22: '22.23.4', 24: '24.22.1', 26: '26.12.1' };
const atLeast = (version, min) => {
  const [a, b] = [version, min].map((v) => v.split('.').map(Number));
  const i = a.findIndex((n, j) => n !== b[j]);
  return i < 0 || a[i] > b[i];
};
const nodeOk = (version) => {
  const major = Number(version.split('.')[0]);
  const newest = Math.max(...Object.keys(NODE_LINES).map(Number));
  if (major > newest) return major % 2 === 0; // an even line newer than this release knows of; odd lines get no long-term support
  return NODE_LINES[major] !== undefined && atLeast(version, NODE_LINES[major]);
};
if (!nodeOk(process.versions.node)) {
  const lines = Object.values(NODE_LINES).join(', ');
  console.error(`security-pranks-audit needs a supported Node line at its current security release (${lines}, or later on the same line); this is ${process.versions.node}.`);
  process.exit(2);
}

const args = process.argv.slice(2);
const flag = (n) => args.includes(n);
if (flag('--version') || flag('-v')) {
  console.log(VERSION);
  process.exit(0);
}
const valueOf = (name) => (flag(name) ? args[args.indexOf(name) + 1] : undefined);
const comparePath = valueOf('--compare');
const base = valueOf('--base');
const logsPath = valueOf('--logs');
const tags = args.filter((a, i) => args[i - 1] === '--tag');
const domains = args.filter((a, i) => !a.startsWith('-') && !['--compare', '--base', '--logs', '--tag'].includes(args[i - 1]))
  .map((d) => d.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase());
if (base) {
  let u;
  try { u = new URL(base); } catch { u = null; }
  if (!u || !['http:', 'https:'].includes(u.protocol)) { console.error(`--base needs an http(s) URL, like http://localhost:3000 (got ${base})`); process.exit(2); }
}

if (logsPath) {
  const tally = logTally({ tags });
  try {
    for await (const line of createInterface({ input: createReadStream(logsPath), crlfDelay: Infinity })) tally.add(line);
  } catch (e) { console.error(`Couldn't read ${logsPath}: ${e.message}`); process.exit(2); }
  const rep = tally.result();
  console.log(flag('--json') ? JSON.stringify(rep, null, 2) : formatLogs(rep).join('\n'));
  process.exit(0);
}

if (!domains.length || flag('--help') || flag('-h')) {
  console.error(`security-pranks-audit ${VERSION}

Checks that a site answers secret-hunting probes (/.env, /.git/config, SSH
keys, wp-config.php...) safely: a 4xx status, nothing shaped like a
credential, no-store, noindex, plain text, no retaliation.

Usage:
  security-pranks-audit <domain> [--json] [--compare previous] [--base url]
  security-pranks-audit --matrix <domain> <domain> ...
  security-pranks-audit --logs <access-log> [--tag text ...] [--json]

Options:
  --json        print the results as JSON
  --matrix      score several sites and print a markdown status page
  --compare f   list what changed since a previous run: a status page from
                --matrix or a saved --json report
  --base url    score a local or preview build as the domain, before you
                deploy (http://localhost:3000)
  --logs f      count secret-hunting probes in an exported access log
                (combined log format or JSON lines), by kind, status and
                client family; prints counts, never addresses
  --tag text    with --logs: count requests whose query carries this text,
                the tag your prank's links use (repeat for each tag)

Run it only against sites you run: its requests look like the scanners it
checks for, in your logs and to a firewall. It sends about 20 requests,
plus up to 10 sitemap pages, a few at a time.`);
  process.exit(domains.length ? 0 : 2);
}

if (flag('--matrix')) {
  if (base) console.error('--base works with a single domain; ignoring it for --matrix.');
  // A few sites at a time: each site still gets only a few requests in flight.
  const reports = await mapLimit(domains, 3, (d) => audit(d));
  const pinned = `security-pranks-audit@${VERSION.split('.')[0]}`; // the major version, as STANDARD.md says to pin it
  let previous = null;
  console.log(matrix(reports, `npx ${pinned} --matrix ${domains.join(' ')}`));
  if (comparePath) {
    let text;
    try { text = readFileSync(comparePath, 'utf8'); } catch (e) { console.error(`Couldn't read ${comparePath}: ${e.message}`); process.exit(2); }
    for (const rep of reports) {
      previous = parsePrevious(text, rep.domain);
      if (!previous) { console.error(`${rep.domain}: not in ${comparePath}`); continue; }
      console.error(`${rep.domain}: ${formatComparison(compareResults(previous.results, rep.results), `${previous.date ?? 'the previous run'} (${comparePath})`).join('\n')}`);
    }
  }
  process.exitCode = reports.some((rep) => rep.results.some((r) => r.level === 'required' && r.status === 'fail')) ? 1 : 0;
} else {
  let previous = null;
  if (comparePath) {
    let text;
    try { text = readFileSync(comparePath, 'utf8'); }
    catch (e) { console.error(`Couldn't read ${comparePath}: ${e.message}`); process.exit(2); }
    previous = parsePrevious(text, domains[0]);
    if (!previous) { console.error(`${comparePath} has no results for ${domains[0]}`); process.exit(2); }
  }
  const rep = await audit(domains[0], { base: base ?? null });
  const since = previous ? `${previous.date ?? 'the previous run'} (${comparePath})` : null;
  const changes = previous ? compareResults(previous.results, rep.results) : null;
  if (flag('--json')) console.log(JSON.stringify(changes ? { ...rep, changes: { since: previous.date, ...changes } } : rep, null, 2));
  else {
    const label = { pass: 'PASS', warn: 'WARN', fail: 'FAIL', skip: 'skip' };
    console.log(`Agent security pranks: ${rep.domain}${rep.base ? ` via ${rep.base}` : ''}  (security-pranks-audit v${VERSION}, ${rep.checked_at.slice(0, 16)}Z)`);
    console.log(`Probed ${rep.origin}. Prank found: ${rep.prank ? 'yes' : 'no'}. Framework: ${rep.framework ?? 'not detected'}.`);
    for (const level of LEVELS) {
      const rows = rep.results.filter((r) => r.level === level);
      if (!rows.length) continue;
      console.log(`\n${{ required: 'Required', recommended: 'Recommended' }[level]}`);
      for (const r of rows) console.log(`  ${label[r.status]}  ${r.id.padEnd(3)} ${r.name.padEnd(36)} ${r.detail}`);
    }
    console.log(`\nScore on ${rep.checked_at.slice(0, 10)}: required ${score(rep.results, 'required')}, recommended ${score(rep.results, 'recommended')}`);
    if (changes) console.log(`\n${formatComparison(changes, since).join('\n')}`);
    console.log('\nNot scored, so check these yourself:');
    for (const [id, what] of REVIEW) console.log(`  ${id.padEnd(4)} ${what}`);
  }
  process.exitCode = rep.results.some((r) => r.level === 'required' && r.status === 'fail') ? 1 : 0;
}
