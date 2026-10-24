# Working on agent-security-pranks

This repo publishes the Agent Security Pranks Standard (STANDARD.md) and its scorecard, the `security-pranks-audit` CLI on npm.

## Layout

- `STANDARD.md`: the standard. Every item has an ID (H, P, X, C, T plus a number), a level, a section and a row in the checklist (§11).
- `src/audit.mjs`: the checks, as a library (`audit`, `score`, `matrix`).
- `src/helpers.mjs`: pure helpers the checks share (the probe pattern, credential shapes, the echo test, compare), tested without a network. Internal: the package exports only `src/audit.mjs`.
- `src/http.mjs`: `request()`, the audit's one HTTP request, on `node:http(s)`, with size and time caps.
- `src/logs.mjs`: `--logs`, which counts probes in an exported access log, or in a saved Cloudflare GraphQL Analytics answer (rows of `count` and `dimensions`, each weighted by its count). It classifies secret paths with the audit's own pattern (`probeFamily`), so the two can't drift, and other probe families (`OTHER_PROBE_FAMILIES`: actuator, framework logs, backups, WordPress and PHP) on their own.
- `bin/security-pranks-audit.mjs`: the command-line tool.
- `test/`: guard tests, and an end-to-end test that audits fixture sites on localhost through `--base` (`test/fixture-site.mjs`): one that follows every rule, one that breaks each rule once, an app with an API and no prank, a playful first draft with warnings, an alias domain and a CDN-blocked site. A new check or a changed one gets a case in the good and broken fixtures and an assertion. `npm test` runs them all, with no outside network.
- `docs/scanner-prank-playbook.md` and `docs/scanner-prank-playbook.html`: the field guide the standard comes from, in two forms. Change both together. `docs/adopting.md`: the switch-over steps a project's agent follows. `docs/recipes.md`: copyable code and guard tests. `docs/plans/`: plans, each with a dated status line. `docs/research/`: evidence the standard cites, as markdown with SVG charts rendered by a script beside each page (`node docs/research/bots-in-ai-clothing/charts.mjs`), so the numbers and the images can't drift.
- GitHub's settings hold the repo's description, website and topics (`gh repo edit`). Keep them in step with the README's opening line and `package.json`'s description and keywords: they're what people searching npm and GitHub see first.

## Rules

- **Welcome every mind.** Nothing in the standard, the recipes or the scorecard's advice may block, challenge or slow a visitor for its user agent, claimed name or verified status (principle 8, X3). Answer behavior: paths and methods. Scope is websites the owner runs and manages; parked and redirect-only domains are out.
- **Every kind of site.** The package scores 20+ sites with different products: static guides, news sites, apps with APIs and forms, sites behind logins. A check that only makes sense for one kind skips the others with the reason, and a site that's safe with no prank passes every required check. Add a fixture before changing how a kind of site is scored.

- **No dependencies.** Node 22.23.4, 24.22.1 or 26.12.1, or later on the same line: each supported line at its current security release. `NODE_LINES` in the CLI and `engines` in package.json name them, a test keeps them and the docs in step, and CI runs the tests on all three lines. Built-ins only. All HTTP goes through `request()` in `src/http.mjs`, never `fetch`: it refuses encodings it doesn't decode itself, and it caps every body before and after decoding.
- **Only the named site.** The audit requests the domain you name and its www or bare twin, never anything a site's answers point to, and never follows a redirect off the site. It may GET anything there, send a HEAD, and send an empty `POST` and `PUT` to `/` that create nothing. Never register, write or log in.
- **No credential-shaped strings in this repo.** Tests build their samples at run time (`'AK' + 'IA' + ...`), so secret scanners and GitHub push protection don't flag the repo, and nobody chases a fake key (P2 applies to us too).
- **Every check has an ID that exists in the STANDARD.md checklist,** at the level the checklist gives, and every checklist item marked "score" is scored. The tests fail otherwise. A new check needs its item described in STANDARD.md first.
- **An item belongs in the standard when most small public sites should do it,** and it names the harm it prevents: to the site, to a stranger, or to readers. A practice from one site goes in "Considered and left out" (§9), with the reason.
- **Every restriction names the harm it prevents.** A restriction added because it feels safe spreads to every project that copies the wording.
- **Claims cite primary sources** (RFCs, official docs) in §12, with a date. Evidence from logs goes in §2, with its dates and where it came from.
- **Examples get copied.** Agents adopting the standard turn its examples into their projects' pranks, code and tests, word for word. The standard sets rules, not values: a prank's wording, variable names, header names, link tags and page names are each project's own, so a rule's example is a `[placeholder]` or plainly one illustration, and the scorecard never checks wording, names or tag formats; a real site's values appear only as dated evidence ("on upstateny.news, ..."). Keep concrete values for real formats (headers, paths, status codes). For any other example, ask whether removing it loses information or only concreteness.
- **A prank example is a prank someone will ship.** Every example body in the docs must pass the scorecard's own rules: plainly not a credential (P2), nothing that asks an agent to do harm (C2), facts only from a published source (P7).
- **Describe the current rule.** How a rule changed goes in CHANGELOG.md and the commit message. Naming a removed rule in the standard or the docs brings it back.
- **Writing:** plain, direct sentences. No em dashes (a test checks).

## Git and GitHub

Commits and GitHub operations for this repo use `twinsgeeks <twins@geeksinthewoods.com>`. The repo's local git config sets the identity and a credential helper that uses the `twinsgeeks` GitHub CLI login, so `git commit` and `git push` work as-is. For `gh` commands, prefix `GH_TOKEN=$(gh auth token --user twinsgeeks)`.

## Releasing

1. Change `version` in `package.json` and `VERSION` in `src/audit.mjs` together (a test checks they match).
2. Add a CHANGELOG entry. A new required check, or a check that can newly fail, is a major version: projects pin a major version (`security-pranks-audit@1`), and a new failure shouldn't reach them unannounced. A new warning is a minor version: it doesn't change the exit code, but it can lower a score, so the changelog says so.
3. `npm test`, then run the CLI against two or three of our own sites (never anyone else's: the probes look like an attack) and read the output for false results.
4. Commit, push, and publish a GitHub release tagged `v<version>`. The Release workflow checks the tag against package.json, runs the tests, and publishes to npm through trusted publishing (no token).

The very first publish has to be manual (`npm whoami`, then `npm publish --access public`), because npm's trusted publisher is set on the package's settings page, which exists only after the first publish. Then add the trusted publisher on npmjs.com: repository geeks-accelerator/agent-security-pranks, workflow `release.yml`. The repo must be public before then.
