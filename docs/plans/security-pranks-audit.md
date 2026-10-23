# Plan: turn the Scanner Prank Playbook into a standard and a scorecard

Written 2026-10-23, from [the playbook](../scanner-prank-playbook.md), using [agent-and-search-readiness](https://github.com/geeks-accelerator/agent-and-search-readiness) and its package [readiness-audit](https://www.npmjs.com/package/readiness-audit) as the model.

**Status (2026-10-23):** steps 1 to 7 are built: the repo skeleton, STANDARD.md (18 items, 12 scored), the two fixture sites, the CLI with `--matrix`, `--compare`, `--base` and `--logs`, adopting.md, recipes.md, CI and the release workflow. `npm test` passes 30 tests with no outside network. A first run against upstateny.news scored 10 of 10 required and 2 of 2 recommended, after a fix for Cloudflare's WAF blocking `/wp-config.php` (an edge block is now a safe failure, not graded as the prank). The GitHub repo exists (private).

Still open, each needing the owner:
- **Reserve the npm name** with a manual `0.0.0-stage` publish, then add the trusted publisher on npmjs.com.
- **Make the repo public** before the 1.0.0 release, and set its description, topics and homepage.
- **Step 8:** the list of our 10+ sites for `--matrix`, and a day of logs from each for the before and after counts (T2).
- **H2's source:** cite the 2026 Next.js image optimizer advisory by its ID in §12.

## Names

The two projects follow one pattern: the repo is named after the standard, and the package is named for what it does.

| | Readiness | Pranks |
|---|---|---|
| Repo | `geeks-accelerator/agent-and-search-readiness` | `geeks-accelerator/agent-security-pranks` |
| Standard | Agent and Search Readiness Standard | Agent Security Pranks Standard |
| Package and CLI | `readiness-audit` | `security-pranks-audit` |

"Security" is the word people search for, and "prank" is what sets the package apart. `prank-security-audit` was turned down because it reads as a fake security audit.

## The problem

Our sites get a lot of traffic from bots and agents hunting for leaked secrets (`/.env`, `/.git/config`, SSH keys). The playbook says how to answer them with a harmless joke, and which checks prove the joke is safe. We're rolling it out across 10+ of our own sites. Right now it's an essay that each project reads once, and nothing tells us whether each live site still follows the rules after its next deploy. agent-and-search-readiness fixed the same problem with a numbered standard plus a read-only CLI that scores live sites against it. This package does the same for scanner pranks.

**Scope:** this package scores sites. Pranks that test how an AI agent behaves score the agent, not the site, so they're out of scope. The bridge between the two is item C2, a note for AI agents inside the prank.

## What ships

- **`STANDARD.md`, the Agent Security Pranks Standard:** the playbook's rules as items. Each item has an ID, a level, the reason for that level and the harm it prevents, and a checklist row.
- **`security-pranks-audit`:** a CLI with no dependencies. It sends a small fixed set of probe requests to a site and prints a pass, warning or failure for each check, with the ID and the reason. It exits 1 when a required check fails, so a deploy can gate on it. `--matrix` scores all our sites in one run and writes a status page.
- **`docs/`:** the playbook (kept as the readable guide), `adopting.md` for a project's coding agent, and recipes for copyable guard tests.
- **The usual repo pieces**, copied from the readiness repo and adapted: README, AGENTS.md with CLAUDE.md importing it, CHANGELOG, CONTRIBUTING, SECURITY, LICENSE (MIT), CI, a trusted-publishing release workflow, and issue templates.

## How this plan is built

- **Copy the readiness repo's shape and rules.** No dependencies, Node 26.12.1 or later, built-ins only. All HTTP goes through one `request()`. Every check carries an ID that appears in the checklist, and a test enforces that. Write in plain sentences with no em dashes.
- **Detect, don't add flags.** readiness 2.0 removed `--no-api` and started detecting the API the way it detects MCP. This package starts that way: a check that doesn't apply to a site skips itself, with the reason, rather than relying on a flag.
- **Every restriction names its harm.** The playbook already does this ("a `200` on `/.env` marks you as found"), so each item keeps its reason.
- **The playbook stays the guide, and the standard becomes the reference.** The playbook links to item IDs. The standard doesn't repeat the playbook's prose.

## Order

1. Set up the repo skeleton and reserve the names.
2. Write STANDARD.md from the playbook.
3. Build the fixture sites and the end-to-end test.
4. Build `security-pranks-audit`'s checks.
5. Add `--matrix` for our sites.
6. Add `--logs` (before and after measurement).
7. Write `adopting.md` and the recipes.
8. Run it across our sites, then release 1.0.0.

Steps 2 and 3 can start together. Step 4 needs both, and step 5 needs step 4. Step 6 is independent once step 1 is done.

## 1. Repo skeleton and names

- `git init`, `package.json` (`"name": "security-pranks-audit"`, `"type": "module"`, `bin`, `exports`, `engines.node >=26.12.1`, `"test": "node --test"`), `.gitignore`, and LICENSE.
- **Node version:** the CLI exits with a message on an older Node, since `engines` only warns. readiness requires 26.12.1 or later for the 2026-10-21 security release (a Brotli decoder bug and two TLS hostname bypasses).
- **Reuses:** the readiness repo's `src/http.mjs` as the starting point for `request()`. It refuses encodings it doesn't decode itself, and it won't follow redirects to private addresses.
- **GitHub identity:** commits and GitHub actions for this repo use `twinsgeeks <twins@geeksinthewoods.com>`, as in the readiness repo. The repo's local git config sets it (done 2026-10-23). This machine's global git identity and active `gh` account are a different user, so switch `gh` to `twinsgeeks` before creating the repo or a release.
- **Reserve the names early.** Create `geeks-accelerator/agent-security-pranks` on GitHub, and publish a placeholder `0.0.0-stage` to npm by hand, as readiness did. npm's trusted publishing is set up on the package's settings page, which exists only after the first publish.
- **Repo settings:** point the homepage at the npm page. Add topics in search words, such as `security`, `security-headers`, `vulnerability-scanner`, `dotenv`, `honeypot`, `bot-traffic`, `nextjs`, `nginx`, `express` and `cli`. The npm description starts with what the audit scores ("Check that your site answers `.env` and `.git` probes safely: 404 status, no credential-shaped strings, no-store, noindex...").
- **Done when** `npm test` runs (and passes with no tests), and both names are held.

## 2. STANDARD.md

Proposed ID families, taken from the playbook's sections:

| ID | Family | From the playbook |
|---|---|---|
| H | Hardening (make the target smaller) | refuse unused methods, refuse unused framework endpoints, pin and patch the runtime |
| P | Prank rules (keep it a joke) | 404 status, no credential-shaped strings, no-store and noindex, plain text with nosniff, sanitized echo, narrow matching, quoted facts, ordinary 404s untouched |
| X | Never (things that stop being a prank) | no retaliation (zip bombs, tarpits, redirects at third parties), no traps that need a 200 |
| C | Content (the menu) | the only secret you have, a note for AI agents, a 404 line for humans, a themed 4xx |
| T | Tests and measurement | checks run against the built server and shown failing once, logs read before and after |

Draft checklist (levels to settle while writing):

| ID | Item | Level | Checked by |
|---|---|---|---|
| H1 | A read-only site answers methods other than GET and HEAD with 405 and `Allow: GET, HEAD`, never a 5xx | R | score |
| H2 | Unused framework endpoints (e.g. `/_next/image`) return 404 | R if true | score, test |
| H3 | Runtime version pinned and patched | Rec | review |
| P1 | Probe paths answer with a 4xx, never 200 | R | score |
| P2 | Nothing in the body looks like a credential | R | score |
| P3 | `Cache-Control: no-store` and `X-Robots-Tag: noindex`, not in the sitemap | R | score |
| P4 | `text/plain` with `X-Content-Type-Options: nosniff` | R | score |
| P5 | An echoed path is printable ASCII with a length cap | R if true | score |
| P6 | The pattern matches no real route | R | score (sitemap URLs), test |
| P7 | Facts in the joke appear word for word in the published source | R if true | test |
| P8 | An ordinary missing page shows the normal 404, with no prank | R | score |
| X1 | No retaliation | R | score (size and time limits), review |
| X2 | No canary traps disguised as a prank | R | score (follows from P1, P2) |
| C1 | The "only secret": something the project already gives away | Rec | review |
| C2 | A note for AI agents that asks nothing harmful | Rec | review |
| C3 | A line for humans on the 404 page, pointing somewhere useful | Rec | review |
| T1 | The checks run against the built server and were each seen failing | R | review |
| T2 | Probe and 5xx counts from logs, before and after | Rec | `--logs` |

- **Sources to cite, with dates:** RFC 9110 (405, `Allow`, 418's status in the registry), MDN or the spec for `X-Robots-Tag` and `nosniff`, and the Next.js image optimizer advisory the playbook mentions. Each claim needs a primary source before it goes in.
- **"Considered and left out":** tarpits, canary tokens used as a joke (both with the playbook's reasons), and pranks that test an agent rather than a site (see Scope).
- **Done when** every playbook rule maps to an item or to "left out", and the playbook links to the IDs.

## 3. Fixture sites and end-to-end test

- **Reuses:** the readiness repo's `test/fixture-site.mjs` pattern: a `node:http` server on localhost, audited through `--base`.
- **Two fixtures:** a site that follows every rule, and a broken one (200 on `/.env`, a fake key in the body, missing headers, the prank on every 404, 500 on `POST /`). Every check should pass on the first and fail on the second. That's the "shown failing once" rule, built into CI.
- **Done when** `npm test` audits both fixtures with no outside network.

## 4. `security-pranks-audit` checks

```
security-pranks-audit <domain> [--base url] [--json] [--compare previous]
security-pranks-audit --matrix <domain> <domain> ...
security-pranks-audit --logs <access-log> [--json]
```

- **Probe set:** a fixed, short list (`/.env`, `/.git/config`, `/.ssh/id_rsa`, `/@fs/..%2f.env`, `/wp-config.php`, `/.aws/credentials`), plus one random missing path, `GET /`, `HEAD /`, and an empty `POST /` and `PUT /` that create nothing. About 15 requests, a few at a time. No `OPTIONS`: CORS preflight uses it legitimately.
- **H1, detected:** an empty `POST /` that returns 405 with `Allow` passes. A 5xx fails, since a framework crash with a stack trace in the log is the harm the playbook names. Anything else warns: the site accepts POST, so it isn't read-only, and the line says to return 405 if it should be. No `--read-only` flag.
- **Credential-shape detector (P2):** a list of regexes in `src/helpers.mjs` for common key and token prefixes, PEM headers, and URLs with `user:pass@`, plus a long high-entropy string check. Unit-tested against the playbook's own example bodies, which must pass.
- **Retaliation guard (X1):** cap each probe response's size and time. A body over the cap, or a response that drips slowly, fails X1 and the audit stops reading.
- **P6:** fetch the sitemap and run the site's matched paths. From outside, the audit can only check that no sitemap URL gets the prank body. The full route check is a recipe (step 7).
- **Identify ourselves:** send a `User-Agent` naming `security-pranks-audit` and the repo URL, so the requests are easy to tell apart from real scanners in the site's logs.
- **Only for your own sites.** The probes look like attacks in the target's logs and may trip a WAF. The README and `--help` say to audit sites you run, and `--base` is the normal way to use it before a deploy.
- **Done when** every check has an ID in the checklist (test-enforced) and both fixtures score as expected.

## 5. `--matrix` for our sites

This is the main way we'll use the package: one run across all 10+ sites, and one page that shows which ones are done.

- **Reuses:** readiness's `matrix()` and its markdown status page: a row per check, a column per site, and a summary line per site (required failures, warnings).
- **Concurrency:** the per-site limit (a few requests at a time) still applies, and sites run one after another or a few at once, so the run doesn't look like a burst from one address to a shared host or CDN.
- **`--compare`** reads a previous status page or `--json` report and lists what changed, so a monthly run shows regressions across the network.
- **A sites list:** `--matrix` takes domains on the command line. The README shows a shell one-liner that reads them from a file, rather than adding a config format.
- **CI:** an example GitHub Actions workflow that runs the matrix on a schedule and fails on any required failure, copied from readiness's `examples/github-action.yml`.
- **Done when** the matrix over both fixtures (through `--base`) renders a status page in a test, and `--compare` lists a planted regression.

## 6. `--logs`

- **What:** read an exported access log and count probe requests by path family, status code (especially any 200 or 5xx on a probe), and client family. It prints counts, never addresses.
- **Reuses:** the readiness repo's `src/logs.mjs` (combined log format and JSON lines from Cloudflare, Vercel and Railway), and the same probe pattern the audit uses, so the two can't drift.
- **Done when** a run on a real export reproduces numbers like the playbook's (404 share, probe count, distinct sources, zero hits).

## 7. `adopting.md` and recipes

- Steps for a project's coding agent: read a day of logs, ship the hardening, pick the "only secret", add the prank behind the pattern, add the guard tests, then run `security-pranks-audit --base`.
- Recipes: the playbook's Next.js, Express and nginx snippets, plus guard tests for P6 (every real route, zero matches) and P7 (quoted facts match the source).
- **Done when** a fresh agent can follow it on one real project without asking questions.

## 8. Run it across our sites, then release

- Run `--logs` on each site's logs before rolling out, so there's a baseline.
- Roll out to our sites with `adopting.md`, then run `--matrix` over all of them and read every line. Fix wrong results in the audit before fixing sites.
- Re-run `--logs` after: scanner 5xx should be zero and every probe a 4xx.
- **Release 1.0.0** by the readiness process: `version` in `package.json` and `VERSION` in the code change together (a test checks they match), a CHANGELOG entry, then a GitHub release tagged `v1.0.0` that publishes through trusted publishing. Projects pin `npx security-pranks-audit@1`. A check that can newly fail is a major version. A new warning is a minor version, and the changelog says it can lower a score.
- **Done when** every site's row on the status page has no required failures, and the before and after log counts are written up in the standard with their dates.
