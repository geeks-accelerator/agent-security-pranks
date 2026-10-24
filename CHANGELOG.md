# Changelog

## 1.2.4 (2026-10-24)

`--logs` finds every scanner 5xx it was built to find again, and the audit finds a prank that a varying 404 page hid. From reviews of 1.2.0 to 1.2.3, each fix with a test that fails without it.

- **A redirect no longer means a site serves a method.** Since 1.1.6, a method and path that got a 2xx or a 3xx anywhere in the log counted as served, and its requests weren't probes. On a real Railway log, a scanner's fake Server Action POSTs to `/`, `/api` and `/app` each got a 307 as well as a 500, so all three paths counted as served: the report showed "5xx 4" in its totals, then "Every probe got something other than a 2xx or a 5xx", and exited 0. Only a 2xx, or a 302 or 303 (a form that POSTs and redirects; Express, Django and Rails use 302 by default), counts as served now. A 307 or 308 keeps the method, so it doesn't.
- **A 5xx always counts.** Since 1.2.3, a probe in a family a site may really serve (`.php`, backups, a framework endpoint its pages use) was left out of the exit code whatever its status, so a scanner asking `/_next/image` for a remote SVG and getting a 500, the pattern behind GHSA-2464-fhr4-w9xw, exited 0. The exemption now covers a 2xx only.
- Two tests, each failing on 1.2.3: the scanner's POSTs from that log, and a 5xx on the image optimizer, a `.php` path and a backup file.
- **STANDARD.md H3** cites both incidents of 2026-10-22: the playbook's sites pinned nothing and Railpack chose its default, Node 24.21.0, and another project's range (`>=24.22.1 <25`) resolved to the same version outside it. 1.2.2 gave only the second, under a reason ("if nothing pins your Node version") that described the first. The playbook says the same. T2 and the README say a 5xx always counts.
- **A prank sent like a varying 404 page is found and graded.** Since 1.1.5, on a site whose 404 page differs on every request (a request ID, a nonce), only an env-shaped answer, or one with another status or content type, counted as a prank. A prank in prose, sent as the same plain-text 404 as the site's page, was never found, so P3, P4 and C2 skipped it: a prank with no noindex passed every required check. The scorecard now takes the words the two missing pages share as the page's fixed part, and an answer without every one of them is a prank. When the two share no words, status and content type alone decide, as before. New fixture: `stampedprank`. Can newly fail a site whose varying 404 hid a prank that breaks a required rule.

## 1.2.3 (2026-10-24)

From animalhouse.ai running 1.2.2's `--logs` as a CI gate. Fewer false failures; no check newly fails.

- **A framework endpoint the site's pages use no longer fails `--logs`.** Since 1.2.1, `--logs` exits 1 when a probe got a 2xx or a 5xx, outside families a site may really serve. `/_next/image` wasn't one of those, so a Next.js site whose pages use `next/image` exited 1 on its own image requests: on animalhouse's day of logs, one `200 GET /_next/image` from a page that uses it failed the step. Framework endpoints now count as possibly real traffic, like `.php` and backups: still listed, marked "may be real traffic", and left out of the exit code. H2 already says a site that uses the endpoint keeps it.
- **STANDARD.md T2** names the exception the README already described, and the README's `--logs` row gets its missing period.

## 1.2.2 (2026-10-24)

Docs only, from animalhouse.ai reviewing 1.2.0. No check changes.

- **H3 says what happened at animalhouse, and asks for an exact version.** 1.2.0 read as a host lagging a day ("Railway's builder still chose Node 24.21.0 the day after 24.22.1 shipped"). The project had pinned `>=24.22.1 <25`, and Railpack 0.43 resolved it to 24.21.0, outside the range, without failing the build. So H3 now pins an exact version (a range is a request a builder may not honor), and "done when" asks that the running server report it. The playbook, in both forms, says the same.
- **The release-tag example no longer names an old release.** adopting.md and the README suggested `blob/v1.1.3/docs/adopting.md`, which an agent would copy and follow without 1.1.4 to 1.2.0. They now say to use the latest tag, `blob/v<version>/...`, from the releases page.

## 1.2.1 (2026-10-24)

From four project agents' reports on 1.2.0, each fix with a test that fails without it. Two false failures fixed, `--logs` clearer, and one new exit code.

**Fewer false failures:**
- **X1 retries a silent probe once.** A probe with no answer in 10 seconds, or a body still arriving then, used to fail X1 as "a tarpit" on a single try; one network blip could fail a site. Only a second silence in a row fails it now.
- **H1 doesn't fail a site with nothing at `/`.** An API-only domain whose homepage is a 404 was reported as "a guard refuses reads". Only a `GET` or `HEAD` refused with 405, or a crash, counts as refusing reads; any other answer is noted and fine.

**`--logs`:**
- **Exits 1 when a probe got a 2xx or a 5xx,** like the audit on a required failure, so the before-and-after step (T2) can gate CI. Families a site may really serve (`.php`, backups) are marked "may be real traffic" and don't count toward the exit code.
- **Analytics without query strings** (Cloudflare's Free plan doesn't offer `clientRequestQuery`) says the prank's tags can't be counted from it, instead of suggesting `--tag`.
- **Redirects Cloudflare sends itself** (`originResponseStatus` 0, such as `www` to the bare domain) are labeled "at the edge", not listed as the site redirecting a probe.

**CLI:** several domains without `--matrix` exit 2 with a message, instead of scoring only the first.

**Wording:** P5's skip line says an ordinary 404 has "no HTML hole" (it said "echoes the path escaped", not always true); C1 says "a link that carries a query string" (any query counts, not only tags).

**Docs:** the Cloudflare recipe adds drifts.bot's measured Free-plan limits (30-day queries, 31 days back, 10,000 rows; `userAgent` and `clientIP` available, `clientRequestQuery` not), `originResponseStatus` and `clientRequestHTTPHost`, and states only what was verified about log export. adopting.md drops advice to add noindex and a cache to an ordinary 404, which named no harm.

## 1.2.0 (2026-10-24)

From adopting the standard on drifts.bot (Next.js on Railway, behind Cloudflare's Free plan, an API and an MCP server): its proposals from PR #5, rebuilt on 1.1.6. A new input format, so a minor version.

- **`--logs` reads a saved Cloudflare GraphQL Analytics answer** (`httpRequestsAdaptiveGroups`): rows of `count` and `dimensions`, each weighted by its count, found wherever they sit, so one response, several zones, or several windows joined with `jq -s` all work. A dimension the query left out is reported as missing, not empty, and the report says the counts are sampled and capped at the top rows. An answer with errors and no rows exits 2 with the errors instead of reporting zero probes. It works with `--tag` and with 1.1.6's method handling. Recipe in `docs/recipes.md`, with the limits and Cloudflare's docs in §12.
- **P6: where users choose URLs, exempt those prefixes up front.** The route test proves only that today's slugs pass; the next user's `env-setup` or `notes.php` would get the joke on their own page. Guidance in P6, the recipes and the adopting steps.
- **X3 covers network (ASN) rules too:** no rule added for this standard keys on a network, since a path rule stops probes for everyone and a network rule challenges every agent on it. A network rule a site keeps for unrelated reasons is outside the standard, kept off the API, MCP and discovery paths (§9, recipes, adopting step 9).
- **STANDARD.md §2:** drifts.bot's week of analytics (about 36,000 requests, about 6,000 probes, none got a 2xx), with its limits.

## 1.1.6 (2026-10-23)

From adopting the standard at animalhouse.ai, an app with an API and an MCP endpoint. No check newly fails or warns.

- **`--logs` no longer counts an API's or a form's own traffic as unused methods.** Every request with a method other than GET or HEAD was counted as a probe, so on animalhouse's day of logs 2,310 POSTs were "probes" and 2,217 successful API and MCP calls were listed as "probes that got a 2xx". A method now counts only on a path that never succeeded with it anywhere in the log, which leaves a `POST /` that always gets 405 counted and `POST /api/...` that answers 200 out. On that log the probes went from 5,928 to 3,685, and the probe addresses from 272 to 31. A test covers an API site, and that `result()` gives the same report every time it's called. A method and path that got a 2xx or a 3xx anywhere in the log counts as served, so a form that POSTs and redirects (303) isn't counted either.
- **recipes.md: the prefix exemption is case-sensitive, like routes.** `isProbe` lowercased the path before checking the exempt prefixes, so `/API/.ENV` was exempted as the API, yet the API never saw it, and it got the ordinary 404 page (C1 warns). It now compares prefixes with the decoded path as it came and lowercases only for the pattern.
- **recipes.md: an early return skips the rest of the proxy.** A prank returned from a Next.js proxy before the proxy sets its security headers has none of them, and fails P4 while every page passes. The Next.js recipe says so, next to `plain()`, which sets `nosniff` itself.
- **recipes.md guard tests match the standard:** the probe test accepts `no-store` or a cache of a day or less (P3 allows both since 1.1.0), and the method test accepts an `Allow` that lists more than `GET, HEAD`, as on a site that answers `OPTIONS` for CORS.
- **docs/adopting.md lessons:** the animalhouse lesson no longer says a test checks all 715 sitemap URLs (a script checked them once; the test builds every route from the app's route folders), and three lessons are new: the case-sensitive exemption, the early return, and the `--logs` count on an API site.

## 1.1.5 (2026-10-23)

From a second review, each scorecard fix reproduced on a fixture site before it was made. No check newly fails a site; two stop failing safe sites wrongly, so a patch release.

**Looser (fewer false failures):**
- **A 404 page that differs on every request isn't graded as a prank.** The scorecard counted a probe as pranked when its answer differed from the ordinary 404, and a 404 with a request ID, nonce or timestamp (Vercel's default 404 carries an ID) differs every time. A site with no prank then failed P3 and P4. It now fetches two missing pages; when they differ, only an env-shaped answer, or one whose status or content type differs from the ordinary 404, counts as a prank.
- **P5 grades the prank, not every 404 that echoes the path.** Express's default 404 (`Cannot GET <path>`, escaped) failed P5 for the length cap, on a site with no prank. An ordinary 404 now fails P5 only for an HTML tag from the path coming back unescaped, which is a hole whatever the prank.
- New fixtures: `stamped` (a 404 with a request ID), `express` (Express's default 404) and `reflect` (an ordinary 404 that reflects the path unescaped). The audit sends one more request, a second missing page.

**Docs:**
- **adopting.md** asks the owner whether the site welcomes every agent before changing any bot setting, and which inbox `security.txt` should name, never guessing one. It lists every kind of address `--base` treats as local.
- **examples/github-action.yml** installs the latest Node of its line (`check-latest`), since a runner's cached Node can sit below the security release the CLI requires.
- **recipes.md:** the Next.js recipe says the function must be named `middleware` on Next 15 (it exported `proxy`, which Next 15 never runs), and `replyFor` honors the real-content exemption, as `isProbe` already did.
- **The playbook copy** follows the standard: a cache of a day or less is allowed (P3), and `OPTIONS` isn't refused when anything relies on CORS preflight.
- **STANDARD.md:** the impersonator's 308k requests and its 39% of probes are no longer run together (173k of the 308k were probes); the logs were about 16 hours, from prerendered sites; the Cloudflare AI bot group names are marked as secondary reports; the request counts include the sitemap pages; three claims with no source are reworded or dropped ("flagged by security vendors", "within hours", and how many tools log headers), and the runtime lag now cites the measured case.

**nginx (from ollamaherd.com):**
- **recipes.md and the playbook** gain an nginx guard for H1: a `map` plus a named `error_page` location, so a 405 carries `Allow: GET, HEAD` (nginx's own 405 sends none), with a line to exempt an API's prefix and a commented line to let `OPTIONS` through for CORS preflight.

**From adopting the standard on achurch.ai,** whose ordinary 404 answers every missing path, probes included:
- **An ordinary 404 that echoes a capped or cleaned path is no longer scored as a prank.** The echo test asks for a 600-character path with a line break and a tag in it. A site that caps or cleans the echo, as P5 asks, sent back only part of it, so the path couldn't be taken out of the answer and the answer didn't match the ordinary 404: the scorecard reported "Prank found: yes" while C1 found none, failed P3 for a prank that wasn't there, and passed C2 for it. `withoutPath` now also removes the longest start of the path the answer holds (12 characters or more), as sent, decoded, and decoded with what isn't printable taken out. Fewer false failures only; no check newly fails. A new fixture site, `plain`, has no prank and an ordinary 404 that echoes a capped path.
- **P3's reason says what P1 already does.** A 4xx keeps a prank out of Google's index, which drops 4xx URLs (cited in §12); noindex is the backstop for the day it's served with a 200. P3 stays required, and its failure message says the same.
- **docs/adopting.md:** a site whose ordinary 404 already answers every probe well can let it be the whole answer and decline C1, with noindex and a short cache on the 404 anyway. The one-line prompt (here and in the README) suggests a release tag in place of `main`, so the agent follows the text the owner reviewed.

## 1.1.4 (2026-10-23)

The standard sets rules, not values: the prank's wording, variable names, header names, link tags and page names are each project's own.

- **Tagged links in any format.** C1 counts a link with any query string in the prank's body or headers as tagged; 1.1.x only recognized `ref`, `source` or `utm_source` set to `scanner...`. `--logs` counts follows only for the tags you pass with the new `--tag <text>` (repeat for each), and assumes none otherwise.
- **STANDARD.md, recipes and adopting.md** replace the example header name, header line and tags with placeholders, and say plainly that examples are illustrations: match the rules, not the examples.

## 1.1.3 (2026-10-23)

From a review of `docs/adopting.md` (PR #1), each fix checked against our own sites.

- **`--base` on a local build names the domain as the Host.** It sent `Host: localhost:<port>`, so a server that runs several sites by Host (a multi-site app, a multi-tenant host, a virtual host) answered with its default site, and the scorecard graded that site under the domain's name. On one such app it reported 10 of 10 for a domain while scoring another, and the sitemap check fell back to the homepage. A hosted preview (`https://<branch>.vercel.app`) keeps its own name, since its host routes by it. The fixture sites now answer only for their own domain, and a test checks every request names it.
- **What counts as a local build is wider:** besides `localhost`, loopback addresses and `*.localhost`, also `0.0.0.0`, private network addresses (`10.x`, `172.16-31.x`, `192.168.x`, `fc00::/7`), single-label names like a Docker service (`http://web:3000`) and `*.local`, `*.internal` and `*.test` names. A public hostname (a hosted preview) keeps its own name.
- **Node 22.23.4 and 24.22.1 are accepted,** as well as 26.12.1: each supported line at its current security release (the 2026-10-21 release fixed the same Brotli and TLS bugs in all three). End-of-life and odd-numbered lines still exit 2. CI runs the tests on all three lines. Odd-numbered lines newer than 26 are refused too, not only older ones. CI installs the latest release of each line (`check-latest`), since a runner's cached Node can sit below a line's security release.
- **docs/adopting.md** asks the owner before the deploy, where it used to ask after, and explains exit code 2 (nothing was scored). **STANDARD.md §2** gives the busiest address's count as 1,876 requests (1,737 of them 404s), where it gave the 404s alone, and sets the playbook's figures beside what `--logs` counts on the same log.

## 1.1.2 (2026-10-23)

- **P1's static-site exception is withdrawn.** A 200 on any probe fails P1 again, on every site, whatever the answer's headers say (`X-Static-Site` no longer means anything). The harm P1 prevents is in how scanners, target lists and security vendors read the status code, not in what the site holds, and a 404 carries the same joke. STANDARD.md P1 now warns against it and lists it under "Considered and left out". It shipped earlier the same day in 1.1.0.

## 1.1.1 (2026-10-23)

- **C2 catches a `curl` command with a quoted URL** (`curl -X POST "https://..."`). 1.1.0 caught only unquoted ones, so a prank that hands agents a ready-to-run sign-up command could pass. Found reviewing a draft prank for an agent travel site.

## 1.1.0 (2026-10-23)

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
- **P1's static-site exception:** a purely static site may answer env-file probes with a 200, recorded in its stub and declared with `X-Static-Site: true` on the answer. P1 then warns instead of failing, and P2 to P5 grade those answers like any prank. A 200 on any other probe, or without the header, still fails. Never for an app.
- **C2 reads notes in headers:** an `X-` header on the prank's answers that talks to agents counts as the note, and is checked for orders like the body.
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
