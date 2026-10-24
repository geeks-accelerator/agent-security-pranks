// Guard tests: the scorecard, its version and the standard can't drift apart.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { VERSION, REVIEW, score, matrix } from '../src/audit.mjs';
import { credentialShapes } from '../src/helpers.mjs';

const read = (f) => readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');
const pkg = JSON.parse(read('package.json'));
const source = read('src/audit.mjs');
const standard = read('STANDARD.md');
const inChecklist = (id) => new RegExp(`^\\| ${id} \\|`, 'm').test(standard);
const scoredLevels = () => new Map([...source.matchAll(/const id = '([A-Z]\d+)', name = '[^']*', level = '(\w+)'/g)].map((m) => [m[1], m[2]]));

test('VERSION matches package.json', () => {
  assert.equal(VERSION, pkg.version);
});

test('the docs and the CLI name the Node versions package.json requires', () => {
  // engines.node lists each supported line at its security release: "^22.23.4 || ^24.22.1 || >=26.12.1".
  const versions = [...pkg.engines.node.matchAll(/(\d+)\.(\d+)\.(\d+)/g)].map((m) => m[0]);
  assert.ok(versions.length >= 2, `engines.node should list each supported line, got ${pkg.engines.node}`);
  const table = `NODE_LINES = { ${versions.map((v) => `${v.split('.')[0]}: '${v}'`).join(', ')} }`;
  assert.ok(read('bin/security-pranks-audit.mjs').includes(table), `the CLI should declare ${table}`);
  for (const file of ['README.md', 'STANDARD.md', 'AGENTS.md', 'SECURITY.md', 'docs/adopting.md']) {
    const text = read(file);
    for (const v of versions) assert.ok(text.includes(v), `${file} doesn't name Node ${v}`);
    assert.doesNotMatch(text, /Node \d+ or later/, `${file} names a single Node floor`);
  }
});

test('every check the scorecard runs is in the standard checklist, at the level it gives', () => {
  const levels = scoredLevels();
  assert.ok(levels.size >= 12, `expected at least 12 scored IDs, found ${levels.size}`);
  const short = { required: 'R', recommended: 'Rec' };
  for (const [id, level] of levels) {
    const row = standard.match(new RegExp(`^\\| ${id} \\| [^|]* \\| ([^|]+) \\|`, 'm'));
    assert.ok(row, `${id} is scored but missing from the STANDARD.md checklist`);
    assert.equal(row[1].trim(), short[level], `${id} runs as ${level} but the checklist says ${row[1].trim()}`);
  }
});

test('every checklist item marked "score" is scored, and every item has a section', () => {
  const levels = scoredLevels();
  for (const m of standard.matchAll(/^\| ([A-Z]\d+) \| [^|]* \| [^|]* \| [^|]* \| ([^|]+) \|$/gm)) {
    const [, id, by] = m;
    if (/\bscore\b/.test(by)) assert.ok(levels.has(id), `${id} says "score" but the scorecard doesn't run it`);
    assert.match(standard, new RegExp(`^### ${id}\\. `, 'm'), `${id} has no section`);
  }
});

test('every item the scorecard leaves to review is in the standard checklist', () => {
  for (const [id] of REVIEW) assert.ok(inChecklist(id), `${id} from REVIEW is missing from the STANDARD.md checklist`);
});

test('no em dashes in the docs', () => {
  for (const file of ['README.md', 'STANDARD.md', 'AGENTS.md', 'CHANGELOG.md', 'CONTRIBUTING.md', 'SECURITY.md', 'docs/adopting.md', 'docs/recipes.md', 'docs/scanner-prank-playbook.md', 'docs/research/bots-in-ai-clothing.md', 'docs/research/who-else-talks-to-scanners.md']) {
    assert.doesNotMatch(read(file), /\u2014/, file);
  }
});

test('no code example in the docs is shaped like a credential (P2 applies to examples)', () => {
  for (const file of ['README.md', 'STANDARD.md', 'docs/adopting.md', 'docs/recipes.md', 'docs/scanner-prank-playbook.md', 'docs/research/bots-in-ai-clothing.md']) {
    for (const [, block] of read(file).matchAll(/```[a-z]*\n([\s\S]*?)```/g)) assert.deepEqual(credentialShapes(block), [], `${file}: ${block.slice(0, 60)}`);
  }
});

test('every image and local link in the research page exists', () => {
  const page = read('docs/research/bots-in-ai-clothing.md');
  const targets = [...page.matchAll(/\]\(([^)#\s]+)(?:#[^)]*)?\)/g)].map((m) => m[1]).filter((t) => !/^https?:/.test(t));
  assert.ok(targets.filter((t) => t.endsWith('.svg')).length >= 10, 'the page shows its charts');
  for (const t of targets) assert.doesNotThrow(() => readFileSync(new URL(`../docs/research/${t}`, import.meta.url)), t);
});

test('score counts passes and ignores skipped checks', () => {
  const results = [
    { id: 'P1', level: 'required', status: 'pass' },
    { id: 'P2', level: 'required', status: 'fail' },
    { id: 'H2', level: 'required', status: 'skip' },
    { id: 'C1', level: 'recommended', status: 'warn' },
  ];
  assert.equal(score(results, 'required'), '1 of 2');
  assert.equal(score(results, 'recommended'), '0 of 1');
});

test('matrix lists every check any site ran, even when the first site stopped early', () => {
  const down = { domain: 'down.example', prank: false, framework: null, results: [{ id: 'P1', name: 'Probes answer with a failure', level: 'required', status: 'fail', detail: 'no answer' }] };
  const up = { domain: 'up.example', prank: true, framework: 'Next.js', results: [
    { id: 'P1', name: 'Probes answer with a failure', level: 'required', status: 'pass', detail: 'x' },
    { id: 'C1', name: 'A prank answers the probes', level: 'recommended', status: 'pass', detail: 'x' },
  ] };
  const md = matrix([down, up], 'cmd');
  assert.match(md, /^\| C1 \| A prank answers the probes \| recommended \| – \| ✓ \|$/m);
  assert.match(md, /^\| \| Framework \| \| not detected \| Next\.js \|$/m);
  assert.match(md, /- \*\*P1\*\* Probes answer with a failure \(fail, required\): no answer/);
});
