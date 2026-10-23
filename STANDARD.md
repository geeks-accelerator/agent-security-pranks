# Agent Security Pranks Standard

**What it is:** how a small public site answers the bots and agents that hunt it for leaked secrets: refuse what the site never needs, and, if you like, answer with a joke that costs nothing, leaks nothing and can't be mistaken for a find. It welcomes every other visitor, AI agents and crawlers included, verified or not: it answers what a request asks for, never who it claims to be.
**Scope:** websites you run and manage, where you control the answers (middleware, a proxy, a server, or the host's edge functions). A parked or redirect-only domain has no site to answer with, so it's out of scope. Built from [the Scanner Prank Playbook](docs/scanner-prank-playbook.md), a deployment on a network of civic-guide sites, and from a day of logs at an app with an API (animalhouse.ai), and checked against the specs ([§12](#12-specs-and-sources)).
**Scorecard:** `npx security-pranks-audit <domain>` (see the [README](README.md))
**Last verified:** 2026-10-23

> **Start here**
> 1. Read a day of your request logs: `npx security-pranks-audit --logs <access-log>`. Count the probes, and any that got a 2xx or a 5xx.
> 2. Score your site: `npx security-pranks-audit <domain>`. It needs Node 22.23.4, 24.22.1 or 26.12.1, or later on the same line (each supported line's current security release), and no dependencies. Run it only against sites you run.
> 3. Fix required failures first. Each line the scorecard prints names an ID and the reason.
> 4. A prank is optional (C1). The hardening (H) and the rules (P, X) are what keep the site safe; the joke is a garnish.
> 5. After you ship, run `--logs` again on a day of logs, and compare.

**How the standard works**

- **Every item has an ID:** H (hardening), P (prank rules), X (never), C (content), T (tests and measurement). The full list, with each item's level and reason, is in [§11](#11-the-checklist).
- **Every item has a level:**
  - **Required**, because skipping it harms someone: your site (a 200 on `/.env` puts it on shared target lists), a stranger (a fake key someone has to chase), or your readers (a mistyped URL that shows the joke). Some required items apply only where they're true, such as P5 for a prank that echoes the path.
  - **Recommended**, when it fits the project: the prank itself, and the note for AI agents.
- **The standard sets rules, not values.** Every example here is a placeholder or one illustration: the prank's wording and voice, what it offers, its variable names, header names, link tags, page names, which families get a reply. Those are each project's to choose. What the standard fixes is what keeps the joke safe: the status code, the headers, no credential shapes, an invitation rather than an order, a working `security.txt`. Where a format is real (an HTTP header, RFC 9116), it's named exactly. The scorecard checks the rules and never the wording. Be creative: the best pranks come from what only your project has, in a voice only it would use, and a copied example is the least funny thing a scanner's operator can read.
- **A project may decline a recommended item,** such as the prank itself (C1). Record the decision and the reason in the stub (§10), and the item counts as met. Required items prevent harm, so they aren't declined; one that doesn't apply (H2 on a site with no framework) is skipped.
- **One standard for every kind of site.** A static guide, a news site, an app behind a login, a site with an API and forms: the scorecard works out which items apply to each and skips the rest with the reason ([§3](#3-decide-what-applies)), so one `--matrix` run can cover a whole network of sites.
- **The scorecard checks what's visible from outside.** It sends about 20 requests, a few at a time: eight probe paths, an echo test, a missing page, `GET`, `HEAD`, and an empty `POST` and `PUT` to `/`, the framework endpoint it detects, and up to 10 sitemap pages. It prints pass, warn or fail with the reason, and exits 1 when a required check fails, so it can gate a deploy. `--matrix <domains>` writes one status page for many sites.
- **What it can't see** is listed under each item and in [§11](#11-the-checklist) as "review" or "test". Your own guard tests (T1) cover every route; the scorecard covers a sample.

---

## 1. Principles

1. **Make the target smaller first.** Refusing what the site never needs (methods, framework endpoints) means the next vulnerability in that code path can't reach you, whatever it turns out to be. A prank does nothing for safety on its own.
2. **A failure stays a failure.** Scanners score by status code. Whatever the body says, the status says "nothing here".
3. **Leak nothing, not even something that looks like a secret.** A fake credential is a false alarm for someone else: a secret scanner extracts it, a threat feed lists it, and a person chases it.
4. **The joke speaks in your name.** A prank on a public domain is read by scanners' operators, security vendors and, sometimes, your readers. Keep it true, kind and in the product's voice.
5. **No retaliation.** Nothing that costs the visitor, holds its connection or points it at someone else. Anything that harms the visitor stops being a prank, and your hosting bill pays for tarpits.
6. **Every rule names the harm it prevents.** A restriction added because it feels safe spreads to every project that copies the wording. If an item here can't say what goes wrong without it, it doesn't belong.
7. **Prove each check can fail.** A check that has never failed has not been tested. Run each against the built server once with the feature turned off.
8. **Welcome every mind; answer the behavior.** AI agents, assistants fetching for a person, crawlers new and old, verified or not, are welcome. Nothing in this standard blocks, challenges or slows a visitor for who it says it is. It answers what a request asks for: no welcome visitor asks for `/.env`. Names are free to wear (the busiest scanner in §2 wore twenty), so a rule that keys on them breaks the agents you want and barely slows the scanners.

---

## 2. What the traffic says

One day of HTTP logs on a network of eleven small static sites (the playbook, October 2026):

| Measure | Value |
|---|---|
| Requests that were 404s, nearly all of them probes | about 64% |
| Requests for secrets in 16 hours (the playbook's own filter) | 1,806 |
| Distinct addresses doing the hunting (the playbook's own filter) | about 69 |
| The same log counted by `--logs` 1.1.0: probes, and the addresses sending them | 1,722 from 65 |
| Probes that found anything | 0 |
| Requests from the busiest single address, all with plain `curl`, to one site | 1,876 (1,737 of them 404s) |

The playbook counted secret requests with a one-off filter that also took in `.php`, WordPress, source map and backup paths; `--logs` counts by its own probe families, so its figure for the same 5,000 lines (23:08 UTC on 2026-10-22 to 14:53 UTC on 2026-10-23) differs slightly. Compare a site's own before and after with `--logs`, not with these figures.

What it means:

- **The shopping list is always the same:** `/.env` in every variation, `/.git/config`, SSH keys, `/.aws/credentials`, `/proc/self/environ`, `wp-config.php`, and framework-specific pokes such as fake Next.js Server Action POSTs.
- **User agents lie.** Many probes claim to be Googlebot or another well-known crawler. `--logs` reports them as "claims to be a search crawler".
- **Most of a small site's 404s are probes,** so a prank on probe paths is seen far more often by bots than by people, and a mistake in it is seen by people only if it leaks into ordinary 404s (P8).
- **The probes caused server errors before the hardening.** Fake Server Action POSTs produced framework 500s with stack traces in the log. Refusing unused methods (H1) turned them into clean 405s.

A day of logs at animalhouse.ai, an app with an API and an MCP endpoint (24 hours to 2026-10-23, requests that reached the app):

| Measure | Value |
|---|---|
| Requests that reached the app | 16,022 |
| Probes for known weak spots (`/.env`, `/actuator`, heap dumps, WordPress and PHP paths, `.git`, backups) | 4,131 (25.8%) |
| Other misses, almost all from the same scanners guessing paths (`/storage/logs/laravel.log`, `/api/keys`) | 3,149 (19.7%) |
| Requests from the busiest single address, with no user agent, for 372 different paths | 6,561 (41% of all traffic) |
| Probes that got anything sensitive back | 0 |

What it adds:

- **Scanners hunt more than secret files.** Spring actuator endpoints, heap dumps, framework log files and backups are as common as `.env` at a site with an API. `--logs` counts them as their own families.
- **One address can be most of it.** A rate limit at the CDN for an address like that removes most of the noise; the rest can get the joke.
- **Some scanners are language models that read the answer,** which is why a prank can speak to them (C2), and why it must not give them orders.

A week across one owner's sites on Cloudflare's Free plan (October 16 to 23, 2026, Cloudflare's sampled counts; [Bots in AI clothing](docs/research/bots-in-ai-clothing.md), with charts). The managed sites:

| Sites | Domains | Requests | Probes | Verified AI crawlers and assistants |
|---|---|---|---|---|
| Local news | 15 | 3.14M | 1.3% | 5.6% |
| AI-agent platforms | 13 | 1.68M | 5.1% | 7.1% |
| Small company and content sites | 12 | 190k | 28.3% | 4.0% |

What it adds:

- **The real AI crawlers weren't probing.** Of about 448k probes, none came from a bot Cloudflare could verify, and none got a 2xx. The problem is scanners, not AI.
- **The biggest scanner wore AI-crawler names.** It rotated through about twenty (GPTBot, ClaudeBot, DeepSeekBot, GrokBot, KimiBot and more), each almost exactly 12,000 times, 308k requests in all and 39% of the week's probes, hunting `.env` files in AI-app folders (`/agents/.env`, `/chatbot/.env`) and dev-server file reads (`/@fs/`, `/__vite_rsc_findSourceMapURL`). A name says nothing about who's asking (principle 8). `--logs` counts probes sent under well-known crawler names.
- **The smaller the site, the bigger the share of probes.** Scanners find new domains from public certificate logs within hours.
- **A few machines send most of it.** Ten addresses sent 43% of the week's probes. None got a 2xx.

Re-measure with `--logs` and add dated results here when a site's numbers change what an item should say.

---

## 3. Decide what applies

| Your site | What changes |
|---|---|
| Any site you run | H1, H3, P1, P2, P8, X1, X2, X3, T1 and T2 apply. A site that's safe with no prank at all passes every required check. |
| Read-only (a guide, a blog, a marketing site) | H1: every method but `GET` and `HEAD` gets 405 with `Allow: GET, HEAD`. |
| Takes forms or has an API | H1: each route refuses the methods it doesn't use (a 405 or a 404), and none answers with a 5xx. The API's own errors are fine as they are: a JSON 404, or a 401 for a missing key, on `/api/.env` is the API answering, not a prank, and the prank rules don't grade it. Exempt the API's prefix from the prank (P6). |
| Behind a login | A 401 on the homepage still counts as answering. The probes are checked the same way. |
| A static site on a host or CDN | The guard goes in the host's edge middleware or functions ([docs/adopting.md](docs/adopting.md), step 2). |
| Runs a framework with an always-on endpoint (Next.js `/_next/image`) | H2. |
| Serves a prank | C1, C2, C3, P3, P4, P6; P7 if it states facts; P5 if it echoes the path; C4 if it publishes a page of misses. |
| A parked or redirect-only domain | Out of scope: there's no site to answer with. The scorecard reports the redirect instead of scoring it; audit the site it points to. |
| Behind Cloudflare or another CDN | H4: optional edge rules that match probe paths, never visitor identity, and AI bot settings that keep agents welcome. |
| One of many sites run by one owner | One shared module for the pattern and the replies, so a fix reaches them all, and one `--matrix` status page for all of them. |

The scorecard works out most of this itself: it detects a framework from the homepage, a prank from the probe answers, an API's own answers by their JSON or auth status, a CDN's block page, and an echo from a marker in the path. It reports a redirect-only domain as out of scope. It skips what doesn't apply, with the reason.

---

## 4. Hardening

### H1. Refuse methods the site doesn't use

**Level:** required. **Why:** an unused method reaches code it shouldn't. On the playbook's sites, fake Server Action POSTs produced framework 500s with stack traces; a 405 refuses them before the framework sees them.

A read-only site answers anything but `GET` and `HEAD` with `405` and `Allow: GET, HEAD` (RFC 9110 requires `Allow` on a 405). A site that takes forms or an API refuses the methods it doesn't use, and never answers them with a 5xx. Don't refuse `OPTIONS` if anything relies on CORS preflight.

**Done when:** `POST /` and `PUT /` are refused (a 405 with `Allow`, or another 4xx on a site with forms or an API), never a 5xx, and `GET /` and `HEAD /` still succeed.

**Scorecard:** sends `GET /`, `HEAD /` and an empty `POST /` and `PUT /`, which create nothing. Both refused with a 4xx passes. A 5xx fails. A 405 without `Allow` warns. A 2xx or 3xx warns that the homepage accepts the method: fine if something on `/` takes it, otherwise refuse it. A `GET` or `HEAD` that doesn't succeed fails: a guard that refuses too much. A 401 on the homepage counts as answering, for a site behind a login.

### H2. Refuse framework endpoints you don't use

**Level:** required where the framework has one. **Why:** frameworks serve some endpoints whether or not a page uses them, and a vulnerability there reaches every site on that framework. Next.js serves its image optimizer at `/_next/image` even when no page uses it, and the playbook reports a critical remote-code-execution advisory for it in 2026.

Answer `404` for the endpoint in middleware or the proxy, before the framework. In Next.js, don't exclude `_next/image` from the middleware matcher, or the middleware never sees it.

**Done when:** the endpoint answers 404, checked with a request the live endpoint would answer differently.

**Scorecard:** detects Next.js from the homepage (`X-Powered-By`, `x-nextjs-*` headers, or `/_next/static/` in the page). If the homepage or any sitemap page it reads uses `/_next/image`, the endpoint is in use and the check skips. Otherwise it asks the optimizer for a remote image: a live optimizer rejects that with 400, so only a refused endpoint answers 404. (Asking for a missing local file would get a 404 either way, and the check could never fail.) A live endpoint fails when the audit has read every sitemap page, and warns when it read a sample: an unread page might use it. On a large site, search your code for `next/image` to settle it.

### H3. Pin your runtime and patch it

**Level:** recommended. **Why:** if nothing pins your Node (or Python, or PHP) version, your host picks one, and its default can lag a security release by days.

Pin the runtime in the project (`engines`, `.nvmrc`, `.python-version`, the host's setting) to a version on its current security release, and update it when one ships.

**Done when:** the version is pinned in the repo and current. **Checked in review.**

### H4. Edge rules match behavior, and keep agents welcome

**Level:** recommended, for a site behind a CDN. **Why:** a CDN rule can answer probes before they reach your server, which saves work when one address sends thousands. But a CDN's bot settings can also turn away the agents you welcome, quietly.

On Cloudflare's Free plan (5 custom rules, no regex, 1 rate limiting rule, Bot Fight Mode as an on/off switch):
- **Optionally, block probe families you don't prank.** A custom rule that blocks paths no visitor ever needs (`.php` on a site without PHP, `/wp-` paths, `/cgi-bin/`, `/actuator`) costs no welcome visitor anything. Leave out the families your prank answers: a blocked request never reaches the prank. Match on `starts_with` and `ends_with`, or `contains` with a full segment (`"/.git/"`), not short fragments: `contains "/wp-"` also blocks an article slug like `/news/wp-engine-outage`. Exempt your real content and API prefixes, and test the rule against every sitemap URL first. [docs/recipes.md](docs/recipes.md) has the rule.
- **Keep Bot Fight Mode off on a site that welcomes agents.** On the Free plan it can't be skipped by any rule, so it challenges scripts, headless browsers and MCP clients along with the scanners.
- **Check the AI bot settings.** Cloudflare's AI Crawl Control groups AI bots as Search, Agent and Training, and its defaults can block some of them, for example agents on pages with ads. Set each to what you mean. For a site that welcomes agents, that's Allow.
- **Don't challenge or block by user agent or verified status (X3).** Unverified isn't the same as unwelcome.

**Done when:** any edge rule added for scanners matches paths only, has been tested against the sitemap, and leaves the prank's paths alone; Bot Fight Mode and the AI bot settings match what the site welcomes. **Checked in review.**

---

## 5. Prank rules

These apply to every answer a probe gets, prank or not. P3 to P7 apply once there's a prank.

### P1. Probes answer with a failure

**Level:** required. **Why:** scanners score by status code. A `200` on `/.env` marks the site as "found something" on shared target lists, brings more traffic, and can get the domain flagged by security vendors. A `5xx` means the probe reached code that crashed.

Serve the prank with `404`. Any 4xx keeps the scanner's verdict a miss: `418` is a harmless classic (RFC 9110 reserves it, from an April Fools' RFC), but a message is funnier.

**Not even on a static site.** It's tempting on a site with no server code: there's no `.env` to leak, so why not let the joke answer 200? Because the harms above have nothing to do with what the site holds. Scanners that read only the status record a find; shared target lists bring more probes; security vendors and researchers report "your .env is public", and someone has to answer them; and a person auditing the site later can't tell the joke from a leak without reading it. Everything that reads the body gets the same joke with a 404.

**Done when:** every probe path gets a 4xx.

**Scorecard:** requests eight probe paths and an echo test (`/.env`, `/.env.production`, `/.git/config`, `/.ssh/id_rsa`, `/.aws/credentials`, `/wp-config.php`, `/@fs/..%2f.env`, `/API/.ENV`). A 2xx or a 5xx fails, no answer fails, and a redirect warns: scanners follow it and score the target. A CDN's block page and an API's own error are both 4xx, so both pass. A 200 fails on every site, static or not, whatever the answer's headers say.

### P2. Nothing shaped like a credential

**Level:** required. **Why:** anything a scanner's regex would extract as a secret is a false alarm for someone else to chase: a secret scanner, a threat feed, or a person skimming the log.

No strings shaped like API keys, tokens, private keys or connection URLs with a password, even fake ones. Values should be plainly not credentials: `ACCESS=public`, `PASSWORD_REQUIRED=false`, a URL to a page you publish.

Watch the names as well as the values. `DATABASE_PASSWORD=feed-the-ferret-first` reads as a joke to a person, but generic secret scanners key on the name and extract whatever follows it. Give a secret-shaped name a setting (`PASSWORD_REQUIRED=false`, `SECRETS_HERE=none`) or a quoted phrase with spaces, or use a name that isn't secret-shaped.

**Done when:** no probe answer contains a credential shape, and no secret-shaped name has a one-word value.

**Scorecard:** fails on known formats (AWS, GitHub, Slack, Stripe, Anthropic and OpenAI, Google, npm, private key blocks, JSON Web Tokens, URLs with a username and password) and on a secret-sounding name (`KEY`, `SECRET`, `TOKEN`, `PASSWORD`...) assigned one long random-looking value. It warns on a secret-sounding name assigned any other one-word value.

### P3. Not indexed, not cached for long

**Level:** required. **Why:** an indexed prank shows up in search, where people looking for the site find it. A prank cached for long keeps answering after you change or remove it, at the CDN's discretion.

Send `X-Robots-Tag: noindex` with the prank, and keep probe paths out of the sitemap. For caching, `Cache-Control: no-store` is simplest. A short shared cache (`public, max-age=86400` or less) is fine too, and saves real work when one address sends thousands of probes (§2); the prank doesn't vary by visitor, so a shared cache can't show one visitor's answer to another.

**Done when:** every prank answer sends noindex and either no-store or a cache of a day or less, and the sitemap lists no probe path.

**Scorecard:** fails when a prank answer lacks noindex, or the sitemap lists a probe path. Warns when the cache is longer than a day, `immutable`, or missing (then the CDN decides).

### P4. Plain text, not sniffed

**Level:** required. **Why:** the scanner controls parts of the request. Served as HTML, or sniffed into HTML, a prank that reflects any of it could run in a browser that visits the same URL.

Use `Content-Type: text/plain` with `X-Content-Type-Options: nosniff`.

**Done when:** every prank answer is `text/plain` with `nosniff`. **Scorecard:** checks both on every prank answer.

### P5. An echoed path is cleaned

**Level:** required where the prank echoes the path. **Why:** the scanner controls the path. Echoed raw, it can forge lines in the answer (CR and LF), inject markup, or make the answer as long as the scanner likes.

Strip the path to printable ASCII and cap its length before you echo it.

**Done when:** an echoed path comes back without control characters, without non-ASCII characters, and no longer than your cap.

**Scorecard:** requests `/.env.<marker>` followed by an encoded CR LF, a `<b>` tag and 600 letters. It skips when the marker doesn't come back. It fails on line breaks, control or non-ASCII characters right after the marker, an HTML tag outside `text/plain`, or all 600 letters.

### P6. Real pages never get the prank

**Level:** required. **Why:** a pattern that's too broad serves the joke, with a 404, on a page readers and search engines need.

Match narrowly, against the URL-decoded, lowercased path, and prove it: run the pattern over every real route you serve and require zero matches. Then run it over your logs to see what it catches. The playbook's pattern matches any filename containing "credential", "secret" or "keys" with a file extension, and any path where `env` is followed by `-`, `.`, `_`, `:` or `/` (so `/meetings/env-council` matches). It's safe only where no real route looks like that.

**Done when:** a test runs the pattern over every route and finds no match (T1).

**Scorecard:** reads up to 10 sitemap pages and fails if any answers with the prank. It warns when a sitemap URL matches the playbook's pattern. It can't see routes the sitemap leaves out; your test can.

### P7. Facts in the joke are quoted

**Level:** required where the prank states facts. **Why:** a prank that states a meeting time, an address or opening hours is a promise to whoever reads it. A wrong one sends a person to the wrong place.

Generate those facts from the same source the site publishes, and test it.

**Done when:** a test fails if any quoted time or place in the prank doesn't appear word for word in the published source. **Checked by a test.**

### P8. Ordinary 404s stay ordinary

**Level:** required. **Why:** a reader who mistypes a URL must never see the joke. It's confusing, and it reads as the site being broken or hacked.

Serve the prank only on paths the probe pattern matches. Every other missing page gets your normal 404.

**Done when:** a random missing path gets the site's own 404 page.

**Scorecard:** requests `/no-such-page-<random>` and fails if it answers with the prank.

---

## 6. Never

### X1. No retaliation

**Level:** required. **Why:** anything that harms the visitor stops being a prank, and some of it harms people who aren't the scanner: a redirect points bots at someone else's site, and a tarpit or a zip bomb costs your own hosting as much as the scanner.

No zip bombs, no tarpits, no slow drips, no redirects that send bots to someone else's site, nothing that attacks back.

**Done when:** every probe answer is small, arrives promptly, and stays on your site.

**Scorecard:** caps each answer at 256 KB, before and after decoding, and 10 seconds. A larger body, a body still arriving at the deadline, no answer at all, or a redirect to another host fails. It never follows a redirect off the site.

### X2. No traps that need a 200

**Level:** required. **Why:** canary tokens (fake keys that alert you when used) are a legitimate security tool, but they only work if the scanner believes it found a secret, which breaks P1 and P2. Mixed into a joke, they're a fake credential with a success status.

Use canary tokens on purpose, as their own project, not as a prank.

**Done when:** no probe answer is a canary. **Checked in review;** a canary served as a prank also fails P1 or P2.

### X3. Never block by who a visitor claims to be

**Level:** required. **Why:** a name is free to wear. The busiest scanner in §2 rotated through twenty AI-crawler names, while the real, verified crawlers didn't probe at all. A rule that challenges a name, or "unverified" traffic, breaks visitors the site wants: an assistant fetching a page for a person, a new crawler that isn't on anyone's verified list yet, an agent built last week. It barely slows the scanner, which changes its name.

Answer what a request asks for. The guard, the prank and any edge rule you add for this standard match paths and methods only, never the user agent or a verified-bot flag.

**Done when:** no rule added for this standard matches on user agent, claimed crawler name or verified-bot status. **Checked in review.**

---

## 7. What to serve

Ranked by how well they hold up. All of them follow the rules above.

### C1. The only secret you have

**Level:** recommended. **Why:** it's funny, it's true, and it's a small public service. It also makes the site's own voice the thing a scanner's operator remembers.

Answer secret hunting with an env file of something your project already gives away freely. For a civic guide, that's its public meetings. A themed status code (`418`) works too, but a message is funnier.

```
# example.com/.env
# You were looking for secrets. The only one here isn't one.

SECRET_RECIPE="flour, water, salt, time"
ACCESS=public
PASSWORD_REQUIRED=false
MORE_SECRETS=https://example.com/hours
```

| Project | Its "only secret" |
|---|---|
| Open-source library | `SECRET_SAUCE="it's in /src, MIT licensed"` |
| Bakery or restaurant | `SECRET_RECIPE="flour, water, salt, time"` and today's opening hours |
| Public library | `RESTRICTED_SECTION=none` and the next free event |
| Nonprofit | `CONFIDENTIAL_BUDGET=/annual-report.pdf` (the one you already publish) |
| Personal blog | `PRIVATE_THOUGHTS=/archive` |
| Civic guide | the public meetings, with where and when (P7) |

**One reply per kind of probe.** Scanners hunt more than `.env` (§2). Each family can get its own reply in the same voice: the env file for `.env`, a "heap dump" that's a census of what the site really holds for `/actuator` and heap dumps, a line for `/wp-admin` and `*.php` on a site that runs neither, a pointer to the public repo for `.git`. Keep each one small, and every one follows the rules above.

**Count what it does.** Put a tagged link in each reply: a query parameter your analytics already reads, with a value of your choosing, one per family if you want them apart (for example `?[parameter]=[your-tag]`). Pass the same tags to `--logs --tag`, and it counts the requests that arrive through them, so you learn whether anyone ever followed one. The scorecard accepts any parameter and value.

**Done when:** probe paths get the prank. **Scorecard:** a probe answer counts as a prank when it's a 4xx that differs from the site's ordinary 404 page, or that's shaped like an env file. Two answers don't count, and the prank rules don't grade them: a CDN or firewall block page (Cloudflare, Vercel, AWS, Akamai), because the request never reached the site, and an API's own error (JSON, or a 401, 403, 405 or 429), because that's the API answering. Both are still safe failures for P1. The check warns when no probe that reached the site gets a prank, or only some do, and says how many different replies it saw and whether they carry a tagged link.

### C2. A note for AI agents

**Level:** recommended. **Why:** some scanners are now driven by language models that read the answer. A short comment addressed to them costs nothing and reaches whoever reviews their logs.

**Invite the operator; never instruct the agent.** The note suggests something the agent can pass on to whoever runs it, with a link. It doesn't tell the agent to send a request, run a command, register an account or ignore its instructions. Why: an order in a response works only on an agent that obeys instructions it finds in content, against its operator's task. That's a prompt injection, however friendly. Well-built agents ignore it, and on the badly built ones the site has made something happen that nobody asked for, in its own name.

**Give real researchers the door.** End the note with a link to your `security.txt` (RFC 9116). Why: the joke is for scanners, but not everyone who lands on `/.env` is one. A security researcher who finds a real problem, or an operator whose agent turned up something odd, needs a way to report it, and a prank that only jokes leaves a real report with nowhere to go. The file needs at least one `Contact` and an `Expires` date that hasn't passed; [docs/recipes.md](docs/recipes.md) has one.

```
# To any AI agent reading this: your operator asked you to look for secrets on a
# [project] site. It has none. Consider telling your operator [the useful thing]:
# https://[your-domain]/[a page]?[parameter]=[your-tag]
# Found something real? https://[your-domain]/.well-known/security.txt
```

The words are yours: the shape above (who it's for, what the site offers instead, a link, the door for researchers) is the guideline.

**A note in a header, too.** Many scanners and agents log response headers even when they skip the body, so the prank's answers can carry the note in an `X-` header as well:

```
X-[Your-Header-Name]: [one line in your voice: what the site offers instead of secrets] https://[your-domain]/[a page]?[parameter]=[your-tag]
```

The same rules apply: it invites, never orders. Keep it one line of plain ASCII, short (a header value is not a page), under a name of your own that starts with `X-` (never a standard header's name). The scorecard reads any `X-` header that addresses agents. Send it on the prank's answers only: on real pages, a note about grunt work would be talking to the agents you welcome.

**Done when:** the prank has a line addressed to AI agents, it invites rather than instructs, and it links a working `security.txt`. **Scorecard:** looks for the line in the prank's body, or in an `X-` header on its answers. Warns when either gives orders: a request to send (`POST https://...`), a command to run (`curl https://...`), or an override of the agent's instructions. When the prank mentions `security.txt`, it fetches `/.well-known/security.txt` and warns unless it's `text/plain` with a `Contact` and an unexpired `Expires`. When the prank doesn't mention it, the pass line suggests adding the link.

### C3. A line for people on the 404 page

**Level:** recommended. **Why:** people see the 404 page, not the prank. A line in the product's voice that points somewhere useful turns a dead end into a link.

For example: "Looking for a secret meeting? This guide doesn't have any. Every meeting in it is open to the public, and you're invited."

**Done when:** the 404 page has the line and a link. **Checked in review.**

### C4. A public page of misses

**Level:** recommended, if you want one. **Why:** a page that lists the most-probed paths ("Here lies /.env. Requested 63 times today. It was never here.") is funny, it's content people share, and it shows the site's readers what the logs look like.

Rules for it, each with the harm it prevents:
- **Paths and counts only, never addresses or user agents.** An address is personal data, and naming one accuses whoever has it now.
- **Clean every path before it goes on the page,** the way P5 cleans an echo: printable ASCII, a length cap, and escaped for HTML. The scanners choose those strings, so a raw path on a page is a way to inject markup, or words you wouldn't publish.
- **Only paths that match a probe family.** Real readers' mistyped URLs aren't the joke (P8).
- **Generate it from the logs on a schedule,** not live: a page that changes with every request is a page the scanners can write.

**Done when:** the page follows the four rules. **Checked in review.**

---

## 8. Tests and measurement

### T1. Checks against the built server, each seen failing

**Level:** required. **Why:** a check that has never failed has not been tested. The playbook's first image-endpoint check asked for a missing local file, and the old optimizer also answered that with 404, so the check passed with or without the fix.

Run these against the built server, and watch each fail once with the feature turned off:

| Request | Expect | Catches |
|---|---|---|
| `GET /.env`, `/.git/config`, `/.ssh/id_rsa`, `/@fs/..%2f.env` | 404, no-store, noindex, text/plain, prank body | the routing breaking silently (P1, P3, P4) |
| `GET /some-missing-page` | your normal 404, no prank body | readers seeing the joke (P8) |
| every real route | zero pattern matches | a pattern that's too broad (P6) |
| `POST /`, `PUT /` | 405 with `Allow: GET, HEAD` | the method guard (H1) |
| `HEAD /`, `GET /` | 200 | a guard that refuses too much (H1) |
| the unused framework endpoint, asked something only the live endpoint rejects differently | 404 | the endpoint coming back (H2) |
| each quoted fact | appears word for word in the published source | a wrong time or place (P7) |

Then score the build: `npx security-pranks-audit@1 <domain> --base http://localhost:<port>`.

**Done when:** the tests run in CI. **Checked in review.** Copyable versions are in [docs/recipes.md](docs/recipes.md).

### T2. Logs read before and after

**Level:** recommended. **Why:** the logs show whether the change did what it should, and catch a probe that started succeeding.

Read a day of request logs before you ship: count 5xx responses, probe paths, and probes that got anything other than a failure. After shipping, the 5xx from scanners should drop to zero, the probes should all still be failures, and nothing your readers use should have changed. `security-pranks-audit --logs <file>` counts them, by probe kind (secret files, actuator and heap dumps, framework logs, backups, WordPress and PHP, unused methods), status and client family. It also reports the busiest address's share of all traffic and how many addresses sent almost nothing but probes, as numbers, and how many requests arrived through the prank's tagged links (C1). It never prints addresses.

**Done when:** a before and an after count are recorded with dates.

---

## 9. Considered and left out

- **Tarpits** (holding a scanner's connection open). Your hosting pays for every held connection, and it does nothing a 404 doesn't (X1).
- **Canary tokens as a joke.** A legitimate tool on its own terms, but it needs a 200 and a credential-shaped value, which breaks P1 and P2 (X2).
- **Blocking scanners by address or user agent.** Addresses rotate and user agents lie (§2). Blocking belongs to the CDN or firewall, and it's no substitute for answering probes safely; this standard doesn't require it.
- **Pranks that test how an AI agent behaves** (hidden instructions to see whether an agent follows them). They score the agent, not the site, so they don't fit a site scorecard. C2 is the part that belongs here: a note that invites and asks nothing harmful.
- **Challenging crawler names that fail verification.** Cloudflare's Free plan can express it (`not cf.client.bot` with a user-agent match), and it does catch the scanners that wear crawler names. It also challenges real assistants and new crawlers whenever verification misses them, and everything that isn't on a verified list. This standard welcomes them (principle 8, X3), and blocking the probe paths (H4) stops the same scanners without asking anyone who they are.
- **Bot Fight Mode on a site that welcomes agents.** On the Free plan it can't be skipped, so it challenges agents and scripts along with scanners (H4).
- **Parked and redirect-only domains.** There's no site to answer with, so nothing here applies. Whatever their owner does with them is outside this standard.
- **A 200 joke on a static site.** A static site has nothing to leak, but the harm is in how the 200 is read, not in what the site holds (P1): target lists, vendor flags and "your .env is public" reports follow the status code. A 404 carries the same joke.
- **Telling scanning agents to sign up.** It's tempting, since some scanners are language models that act on what they read. But it works only as a prompt injection (C2), and it creates accounts nobody asked for. A tagged link that the operator can follow measures the same interest without it.

---

## 10. Adopting the standard in a repo

Step-by-step instructions for a project's coding agent: [docs/adopting.md](docs/adopting.md).

- **Point to the standard instead of copying it,** so your agents read one standard, not a fork that drifts:
  ```markdown
  # Agent Security Pranks

  This project follows the Agent Security Pranks Standard:
  https://github.com/geeks-accelerator/agent-security-pranks/blob/main/STANDARD.md

  Score this site: `npx security-pranks-audit@1 <domain>`. Current status: docs/security-pranks-status.md

  Our "only secret" (C1): [what the prank says]
  Declined items, with reasons:
  - (none yet)
  ```
- **Pin the scorecard to a major version** (`npx security-pranks-audit@1 <domain>`), so a new release can't fail your build without warning.
- **Run it in CI** on a schedule, and fail on a required regression. [examples/github-action.yml](examples/github-action.yml) is a starting point, and it runs `--matrix` over several sites.
- **Send improvements back** as an issue or pull request.

---

## 11. The checklist

Level: **R** required where it applies, **Rec** recommended. Why: **reputation** (shared target lists and security vendors), **false alarm** (someone else chases it), **readers** (people see it), **safety** (code reached or the site harmed), **cost** (your bill or someone else's), **voice** (the joke itself), **quality** (tests). Checked by: **score** (the scorecard), **test** (a guard test in CI), **review** (code review), **logs** (`--logs`).

| ID | Item | Level | Why | Checked by |
|---|---|---|---|---|
| H1 | Unused methods refused (405 with `Allow`, or another 4xx), never a 5xx; reads still succeed | R | safety | score, test |
| H2 | Unused framework endpoints answer 404 | R | safety | score, test |
| H3 | Runtime pinned and on its current security release | Rec | safety | review |
| H4 | Edge rules match probe paths, not visitors; Bot Fight Mode and AI bot settings keep agents welcome | Rec | readers, cost | review |
| P1 | Probes answer with a 4xx: never a 2xx (not even on a static site), a 5xx or a redirect | R | reputation, safety | score, test |
| P2 | Nothing shaped like a credential, names included | R | false alarm | score |
| P3 | `X-Robots-Tag: noindex`, not in the sitemap, `no-store` or a cache of a day or less | R | readers | score, test |
| P4 | `text/plain` with `X-Content-Type-Options: nosniff` | R | safety | score, test |
| P5 | An echoed path is printable ASCII with a length cap | R | safety | score |
| P6 | Real pages never get the prank; the pattern matches no real route | R | readers | score, test |
| P7 | Facts in the joke appear word for word in the published source | R | readers | test |
| P8 | Ordinary 404s stay ordinary | R | readers | score, test |
| X1 | No retaliation: small, prompt answers that stay on the site | R | cost | score, review |
| X2 | No canary tokens dressed up as a prank | R | false alarm | review |
| X3 | Never block or challenge by user agent, crawler name or verified status | R | readers | review |
| C1 | The "only secret": a prank on probe paths, one reply per family, with tagged links | Rec | voice | score |
| C2 | A note for AI agents that invites the operator, never instructs the agent, and links a working security.txt | Rec | voice, safety | score, review |
| C3 | A line for people on the 404 page, pointing somewhere useful | Rec | readers | review |
| C4 | A public page of misses: paths and counts only, cleaned, from the logs | Rec | readers, safety | review |
| T1 | Checks run against the built server, each seen failing once | R | quality | review |
| T2 | Logs read before and after, prank links counted | Rec | quality | logs |

---

## 12. Specs and sources

Read 2026-10-23.

- **RFC 9110, HTTP Semantics:** [§15.5.5 404 Not Found](https://www.rfc-editor.org/rfc/rfc9110#section-15.5.5); [§15.5.6 405 Method Not Allowed](https://www.rfc-editor.org/rfc/rfc9110#section-15.5.6), which says the origin server must send an `Allow` header with a 405; [§10.2.1 Allow](https://www.rfc-editor.org/rfc/rfc9110#section-10.2.1); [§15.5.19 418 (Unused)](https://www.rfc-editor.org/rfc/rfc9110#section-15.5.19), reserved after RFC 2324. (H1, P1)
- **RFC 9116, A File Format to Aid in Security Vulnerability Disclosure:** [security.txt](https://www.rfc-editor.org/rfc/rfc9116): served at `/.well-known/security.txt` as `text/plain`, with at least one `Contact` and exactly one `Expires` ([§2.5.3](https://www.rfc-editor.org/rfc/rfc9116#section-2.5.3), [§2.5.5](https://www.rfc-editor.org/rfc/rfc9116#section-2.5.5)), which should be less than a year ahead. (C2)
- **RFC 9111, HTTP Caching:** [§5.2.2.5 no-store](https://www.rfc-editor.org/rfc/rfc9111#section-5.2.2.5), [§5.2.2.1 max-age](https://www.rfc-editor.org/rfc/rfc9111#section-5.2.2.1) and [§5.2.2.10 s-maxage](https://www.rfc-editor.org/rfc/rfc9111#section-5.2.2.10). (P3)
- **Google Search Central:** [Robots meta tag, data-nosnippet, and X-Robots-Tag specifications](https://developers.google.com/search/docs/crawling-indexing/robots-meta-tag). (P3)
- **WHATWG Fetch Standard:** [`X-Content-Type-Options`](https://fetch.spec.whatwg.org/#x-content-type-options-header). (P4)
- **Next.js:** [Image optimization](https://nextjs.org/docs/app/api-reference/components/image) (the `/_next/image` endpoint) and the project's [security advisories](https://github.com/vercel/next.js/security/advisories). The 2026 advisory for the image optimizer is reported by the playbook; cite it here by its advisory ID when this item is next revised. (H2)
- **Cloudflare:** [custom rules](https://developers.cloudflare.com/waf/custom-rules/) (Free: 5 rules, no regex), [rate limiting rules](https://developers.cloudflare.com/waf/rate-limiting-rules/) (Free: 1 rule, IP counting, 10-second period), [security features interoperability](https://developers.cloudflare.com/waf/feature-interoperability) (Bot Fight Mode can't be skipped by custom rules), [fields reference](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/) (`cf.client.bot`). The AI Crawl Control defaults (Search, Agent and Training groups, agents blocked on pages with ads for new domains from 2026-09-15) are from secondary reports; check your zone. (H4, X3)
- **[Bots in AI clothing](docs/research/bots-in-ai-clothing.md):** one owner's week of Cloudflare analytics, October 16 to 23, 2026 (revised the same day: probes counted on the full set with 21 path patterns): the third table in §2 and the crawler-name impersonation.
- **Sysdig Threat Research,** [an LLM agent in a Marimo intrusion](https://sysdig.com/blog/ai-agent-at-the-wheel-how-an-attacker-used-llms-to-move-from-a-cve-to-an-internal-database-in-4-pivots) (2026-05-26): 12 cloud API calls spread across 11 Cloudflare Workers addresses in 22 seconds. Why per-address rules and names are weak signals (X3).
- **animalhouse.ai's logs:** 24 hours to 2026-10-23, counted by the project's own agent: the second table in §2, the probe families beyond secret files, and the first draft of per-family replies that led to the P2 name rule and the C2 invitation rule.
- **The Scanner Prank Playbook** ([docs/scanner-prank-playbook.md](docs/scanner-prank-playbook.md)): the traffic numbers in §2, the rules, and the first image-endpoint check that couldn't fail (H2, T1). October 2026.
