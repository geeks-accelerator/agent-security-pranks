# Changelog

## 1.1.0 (unreleased)

Fits every kind of website one owner runs and manages (static guides, news sites, apps with an API and forms, sites behind a login), and adds what a day of animalhouse.ai's logs and its agent's first draft of per-family pranks taught. No check newly fails a site that passed 1.0.0; some can newly warn, so a recommended or required score can drop. `@1` pins keep working.

**Can newly warn (scores can drop):**
- **P2** warns on a secret-shaped name (`SECRET_KEY`, `DATABASE_PASSWORD`, `ADMIN_TOKEN`) given a one-word value. A person reads it as a joke; generic secret scanners key on the name and extract it.
- **P3** warns when a prank is cached for more than a day, marked `immutable`, or sent with no Cache-Control.
- **C2** warns when the prank gives the agent orders: a request to send, a command to run, or an override of its instructions. Invite the operator, with a link, instead.

**Looser (fewer false failures):**
- **P3 no longer requires `no-store`.** A shared cache of a day or less is fine, and saves real work when one address sends thousands of probes. noindex and the sitemap rule still fail. The check is renamed "Not indexed, not cached for long".
- **H1 passes any 4xx refusal** of `POST /` and `PUT /`, not only a 405: a site with forms or an API often answers 404. A 2xx or 3xx warns; a 5xx still fails. A 401 homepage counts as answering, for sites behind a login.
- **An API's own errors aren't graded as the prank.** A JSON answer, or a 401, 403, 405 or 429, on a probe like `/API/.ENV` is the API answering. It passes P1 and is left out of P3, P4 and C1's count.
- **H2 looks for `next/image` on the sitemap pages it reads,** not only the homepage, and fails only when it has read every sitemap page; on a larger site it warns. At animalhouse.ai, `/how-it-works` uses the optimizer while the homepage doesn't, and 1.0.0 failed it wrongly.
- **A redirect-only domain** is reported as "redirects to" its target and out of scope, instead of scored. **A CDN that blocks the audit itself** is reported as a warning naming the CDN, instead of scoring its block page.

**New:**
- **Scope and values, stated:** websites you run and manage (parked and redirect-only domains are out of scope), and a site that welcomes every AI agent and crawler, verified or not. Principle 8 ("welcome every mind; answer the behavior") and **X3** (required, review): never block or challenge by user agent, crawler name or verified status.
- **H4** (recommended, review): edge rules that match probe paths, never visitors, with a Cloudflare Free plan recipe; Bot Fight Mode off and AI bot settings set to Allow on sites that welcome agents. Challenging unverified crawler names is in "Considered and left out", with the reason.
- **STANDARD.md §2:** a week across one owner's Cloudflare sites ("Bots in AI clothing"): no verified crawler probed, and the biggest scanner wore twenty AI-crawler names.
- **`--logs`** counts probes sent under well-known crawler names (real crawlers don't probe, so these are disguises), reports claimed AI crawlers as "claims to be", and adds dev-server file reads, other version-control files and infrastructure endpoints as families.
- **C2 asks the prank to link a working `security.txt`,** so a real researcher who lands on `/.env` has a way to report. When the prank mentions it, the scorecard fetches `/.well-known/security.txt` and warns unless it's `text/plain` with a `Contact` and an unexpired `Expires` (RFC 9116); otherwise the pass line suggests adding the link. Recipe and RFC 9116 in §12.
- **C1** reports how many different replies the prank has and whether they carry a tagged link (`?ref=scanner-env`).
- **C4** (review): a public page of misses, with its rules.
- **`--logs`** also counts actuator and heap dumps, framework logs, backups, and WordPress and PHP as probe families; splits traffic into probes, other misses and the rest; reports the busiest address's share of traffic and how many addresses sent almost only probes (counts, never addresses); and counts requests that arrived through the prank's tagged links.
- **STANDARD.md:** a §3 table for each kind of site, animalhouse.ai's day of logs in §2, one reply per probe family and tagged links (C1), "invite the operator, never instruct the agent" (C2), and the caching rule (P3). Recipes for exempting real content prefixes, per-family replies and the page of misses.

## 1.0.0 (2026-10-23)

The first release: the Agent Security Pranks Standard and its scorecard, built from the Scanner Prank Playbook.

- **STANDARD.md:** 18 items in five families: hardening (H1 to H3), prank rules (P1 to P8), never (X1, X2), what to serve (C1 to C3), and tests and measurement (T1, T2). Each has a level, the harm it prevents, a "done when" and a checklist row. Sources in §12.
- **`security-pranks-audit <domain>`:** 12 checks from outside (P1 to P6, P8, H1, H2, X1, C1, C2), in about 20 requests plus up to 10 sitemap pages. It detects the framework, the prank and an echoed path, and skips what doesn't apply. It requests only the named site, never follows a redirect off it, and caps every answer at 256 KB and 10 seconds. Exits 1 on a required failure.
- **`--matrix`** scores several sites, three at a time, into one status page; **`--compare`** lists what changed since a saved page or JSON report; **`--base`** scores a local or preview build.
- **`--logs`** counts secret-hunting probes in an exported access log by kind, status and client family, and lists probes that got a 2xx or a 5xx. Counts only, never addresses.
- Needs Node 26.12.1 or later; the CLI exits with a message on an older version.
