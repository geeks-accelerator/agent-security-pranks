# Agent Security Pranks

[![CI](https://github.com/geeks-accelerator/agent-security-pranks/actions/workflows/ci.yml/badge.svg)](https://github.com/geeks-accelerator/agent-security-pranks/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/security-pranks-audit)](https://www.npmjs.com/package/security-pranks-audit)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**Check how your site answers the bots and agents hunting it for secrets:** `/.env`, `/.git/config`, SSH keys, `/.aws/credentials`, `wp-config.php`. A standard for refusing what your site never needs and answering the rest with a harmless joke, and a command-line audit that probes a live site the way scanners do and checks every answer. No account, no API key, no dependencies.

The standard gives rules and examples, not values: what your prank says, and how, is yours to invent. It's for websites you run and manage, that welcome AI agents and crawlers and are tired of the scanners. It answers what a request asks for, never who it claims to be: nothing here blocks or challenges an agent, verified or not.

```
npx security-pranks-audit example.com
```

```
Agent security pranks: upstateny.news  (security-pranks-audit v1.2.0)
Probed https://upstateny.news. Prank found: yes. Framework: Next.js.

Required
  PASS  P1  Probes answer with a failure         9 of 9 probes answered with a 4xx (403 ×1, 404 ×8)
  PASS  P2  Nothing shaped like a credential     no credential-shaped strings in 10 answers
  PASS  P3  Not indexed, not cached for long     8 prank answers send noindex and no-store or a cache of a day or less; the sitemap lists no probe paths
  PASS  P6  Real pages never get the prank       read 10 of 19 sitemap pages: none answered with the prank
  PASS  H1  Unused methods refused               POST / answers 405, PUT / answers 405, Allow: GET, HEAD
  PASS  H2  Unused framework endpoints refused   Next.js: /_next/image answers 404
  PASS  X1  No retaliation                       every answer within 0.3 seconds, the largest 9.9 KB, no redirects off the site
  ...
Recommended
  PASS  C1  A prank answers the probes           7 of 7 probes that reached the site get a prank (404 text/plain); /wp-config.php blocked by Cloudflare before it reached the site
  PASS  C2  A note for AI agents                 the prank has a note addressed to AI agents in the body, gives them no orders. Add a link to /.well-known/security.txt, so a real researcher has a way to report

Score on 2026-10-24: required 10 of 10, recommended 2 of 2
```

This repo holds:

- **[STANDARD.md](STANDARD.md):** the Agent Security Pranks Standard. What to do, item by item, each with an ID, a level and the harm it prevents: hardening (H), prank rules (P), things never to do (X), what to serve (C), and tests and measurement (T).
- **`security-pranks-audit`:** the scorecard. It checks a live site against everything the standard can verify from outside, 12 checks in about 20 requests plus up to 10 sitemap pages, and lists what it can't see for you to review.
- **[The Scanner Prank Playbook](docs/scanner-prank-playbook.md):** the field guide the standard comes from, with the measurements, the menu of pranks and code for Next.js, Express and nginx.
- **[Who else talks to scanners](docs/research/who-else-talks-to-scanners.md):** joke and decoy answers on probe paths elsewhere, and sites that address AI agents in headers. Most decoys are honeypots served with a 200; none we found combine a safe 404 with an invitation to the operator.
- **[Bots in AI clothing](docs/research/bots-in-ai-clothing.md):** a week of traffic across 56 domains on Cloudflare, with charts. 1 in 12 requests was a probe, none came from a verified AI crawler, and the biggest scanner wore twenty AI-crawler names.

## Why this one

- **Welcoming by design.** The real AI crawlers don't probe: across one owner's sites, none of 448k probes came from a verified bot, and the biggest scanner wore twenty AI-crawler names as a disguise ([the research](docs/research/bots-in-ai-clothing.md)). So nothing here keys on names or verification (X3). It answers the request for `/.env`, whoever sends it.
- **Built from logs.** On a network of eleven small sites, about 64% of requests were 404s, nearly all of them probes: about 1,700 to 1,800 requests for secrets in 16 hours, depending on how they're counted (STANDARD.md §2). Each item says what harm it prevents, and the claims cite RFCs and official docs with dates.
- **It checks that the joke can't backfire.** A prank served with a 200 puts your domain on shared target lists (P1). A fake key in it is a false alarm for a stranger to chase (P2). A prank that leaks into ordinary 404s confuses your readers (P8). The audit fails each of these.
- **Hardening first, joke second.** Refusing unused methods (H1) and framework endpoints (H2) is what keeps the site safe. A prank is optional; a site with none can pass every required check.
- **One tool for every kind of site.** Static guides, news sites, apps behind a login, sites with an API and forms. It detects the framework, the prank, an API's own error answers, a CDN's block page and an echoed path, and skips what doesn't apply with the reason. A redirect-only domain is reported as out of scope rather than scored. A site that's safe with no prank at all passes every required check.
- **It can't be turned against you.** It requests only the site you name, never follows a redirect off it, and caps every answer at 256 KB and 10 seconds, so a site that answers with a zip bomb or a tarpit can't hurt the machine running it.
- **Built for many sites.** `--matrix` scores a whole network into one status page, `--compare` shows what changed since last month, `--base` scores a build before it ships, and `--logs` counts probes before and after.

## How it fits with other tools

| Tool | What it does | Use it with this |
|---|---|---|
| Secret scanners for code ([gitleaks](https://github.com/gitleaks/gitleaks), [TruffleHog](https://github.com/trufflesecurity/trufflehog)) | Find real secrets committed to a repo | They make sure there's nothing to find. This makes sure the live site answers the hunt safely |
| Header graders ([HTTP Observatory](https://developer.mozilla.org/en-US/observatory), [securityheaders.com](https://securityheaders.com)) | Grade a page's security headers | They grade your pages. This grades what probe paths get back |
| CDN firewall rules (Cloudflare, Vercel, AWS) | Block known probes at the edge | Keep them. This recognizes their block pages and checks what gets through to your site |
| [Canarytokens](https://canarytokens.org) | Fake credentials that alert you when used | A legitimate tool, on purpose and on its own. The standard keeps it out of pranks (X2), because a canary needs a 200 and a credential shape |
| [readiness-audit](https://www.npmjs.com/package/readiness-audit) | Scores a site's readiness for AI agents and search | The sister project. Same shape: a standard with IDs and levels, and a zero-dependency scorecard |

## Score a site

It needs Node 22.23.4, 24.22.1 or 26.12.1, or later on the same line (each supported line's current security release), and has no dependencies. It sends about 20 requests, plus the sitemap and up to 10 of its pages (and, when H2 would warn, up to 10 pages the homepage links to), at most four at a time: eight probe paths, an echo test, two missing pages, `GET` and `HEAD /`, an empty `POST` and `PUT /` that create nothing, the framework endpoint it detects, and the sitemap pages. It asks for gzip or deflate and decodes it itself; a body in an encoding it didn't ask for, such as Brotli, is reported rather than read. It prints a pass, warning or failure for each check, with the reason, and exits with code 1 when a required check fails, so it can gate a deploy.

**Run it only against sites you run.** Its requests look like the scanners it checks for, in your logs and to a firewall. It names itself in its user agent (`security-pranks-audit/<version> (+repo URL)`) so you can tell its requests apart.

```
security-pranks-audit <domain> [--json] [--compare previous] [--base url]
security-pranks-audit --matrix <domain> <domain> ... [--compare previous]
security-pranks-audit --logs <access-log> [--tag text ...] [--json]
```

| Option | What it does |
|---|---|
| `--json` | print the results as JSON |
| `--base url` | score a local or preview build as the domain before you deploy (`--base http://localhost:3000`) |
| `--compare file` | list what changed since a previous run: a status page from `--matrix` or a saved `--json` report |
| `--matrix` | score several sites, three at a time, and print one markdown status page |
| `--tag text` | with `--logs`, count the requests that arrive through your prank's links: pass the tag they carry (any format), once per tag |
| `--logs file` | count probes in an exported access log (combined log format, or JSON lines from Cloudflare, Vercel or Railway), or in a saved Cloudflare GraphQL Analytics answer for a site with no log export ([recipe](docs/recipes.md#logs-without-a-log-export-cloudflares-analytics-t2)), each row weighted by its count: secret files, dev-server file reads, actuator and heap dumps, framework logs, backups, WordPress and PHP, infrastructure endpoints, unused methods. By kind, status and client family, with the busiest address's share of traffic, probes sent under well-known crawler names, any probe that got a 2xx or a 5xx, and the prank's tagged links that came back. It prints counts, never addresses. It exits 1 when a probe got a 2xx or a 5xx (a 2xx in families your site may really serve, like `.php` on a PHP site or `/_next/image` on a Next.js site that uses `next/image`, doesn't count; a 5xx always does), so the before-and-after step can gate CI |

From a clone, run `node bin/security-pranks-audit.mjs example.com`.

To check fixes before they ship, score a local build: `npx security-pranks-audit@1 example.com --base http://localhost:3000`. The requests go to the base and are reported under the domain.

## Score all your sites

`--matrix` is built for a network of sites: one run, one status page with a column per site and a "what to fix" list for each. Sites with and without an API, with and without a prank, sit side by side: each is scored on what applies to it. A redirect-only domain in the list shows "redirects to" its target (it's out of scope), and a site whose CDN blocks the audit says so instead of scoring the block page.

```
npx security-pranks-audit@1 --matrix $(cat sites.txt) > docs/security-pranks-status.md
```

`sites.txt` holds one domain per line. Next month, compare against the page you saved:

```
npx security-pranks-audit@1 --matrix $(cat sites.txt) --compare docs/security-pranks-status.md > new-status.md
```

The comparison prints to stderr, one site at a time; the new page goes to stdout. To run it weekly in GitHub Actions and fail on any required failure, see [examples/github-action.yml](examples/github-action.yml).

## What it checks, and what it can't

It checks, from outside:

- every probe gets a 4xx, never a 2xx, a 5xx or a redirect (P1);
- no answer contains anything shaped like a credential, including secret-shaped names like `DATABASE_PASSWORD=` with a joke value (P2);
- the prank sends `noindex`, isn't cached for more than a day, stays out of the sitemap, and is `text/plain` with `nosniff` (P3, P4);
- an echoed path comes back cleaned (P5);
- sitemap pages and an ordinary missing page never get the prank (P6, P8);
- unused methods are refused (a 405 with `Allow`, or another 4xx on a site with forms or an API), never a 5xx, and reads still work (H1);
- Next.js's `/_next/image` answers 404 when no page uses it (H2);
- every answer is small, prompt and stays on the site: no zip bombs, tarpits or redirects to someone else (X1);
- whether there's a prank at all, how many different replies and tagged links it has, and whether its note for AI agents invites the operator rather than giving the agent orders (C1, C2).

It can't see your routes beyond the sitemap, whether the facts in your prank are right, your runtime version, or whether your tests have ever failed. The standard marks those "test" or "review", and [docs/recipes.md](docs/recipes.md) has guard tests for them. A high score is not the goal: a site that never leaks, never crashes on a probe and never shows the joke to a reader is.

## Use it in your project

Point to [STANDARD.md](STANDARD.md) from your repo instead of copying it (§10 has a short stub), and pin the scorecard to a major version: `npx security-pranks-audit@1 <domain>`. To run it on a schedule in GitHub Actions, see [examples/github-action.yml](examples/github-action.yml).

To switch a project over, give its coding agent one line:

> Adopt the Agent Security Pranks Standard in this repo by following https://github.com/geeks-accelerator/agent-security-pranks/blob/main/docs/adopting.md

The agent reads the page when it runs: to have it follow the text you reviewed, put the latest release tag in place of `main` (`blob/v<version>/docs/adopting.md`, from the releases page). [docs/adopting.md](docs/adopting.md) has the step-by-step instructions, with lessons from the first sites that did it.

## Where it comes from

The [Scanner Prank Playbook](docs/scanner-prank-playbook.md) came from a deployment on a network of eleven civic-guide sites, including [upstateny.news](https://upstateny.news), in October 2026: one day of logs, the hardening that turned scanner 500s into 405s, and a prank that answers `/.env` with the region's public meetings. The standard turns its rules into items, each with the harm it prevents, and checks them against the RFCs. Later evidence came from a day of logs at animalhouse.ai, an app with an API, and from [Bots in AI clothing](docs/research/bots-in-ai-clothing.md), a week across one owner's 56 domains on Cloudflare, which is where the standard's welcome for every agent (X3) comes from. It follows the shape of its sister project, [agent-and-search-readiness](https://github.com/geeks-accelerator/agent-and-search-readiness).

An item is in the standard when most small public sites should do it, not because one site happens to. If you find something wrong or out of date, open an issue or a pull request.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a security problem, see [SECURITY.md](SECURITY.md).

## License

MIT
