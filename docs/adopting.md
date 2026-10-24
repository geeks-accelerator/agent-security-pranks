# Adopting the standard: instructions for a project's agent

To switch a project over, give its coding agent one line:

> Adopt the Agent Security Pranks Standard in this repo by following https://github.com/geeks-accelerator/agent-security-pranks/blob/main/docs/adopting.md

The agent reads this page when it runs, not when you read it. To have it follow the text you reviewed, put the latest release tag in place of `main` (`blob/v<version>/docs/adopting.md`, from the releases page).

Everything below is for that agent. The lessons at the end come from the sites that switched over first.

**Scope:** a website the owner runs and manages, where you can change how it answers. A parked or redirect-only domain has nothing to answer with: skip it. **Values:** the standard is written for a site that welcomes every AI agent and crawler, verified or not. Ask the owner whether theirs does before you change any bot setting; that's their decision. Either way, nothing you add for this standard may block, challenge or slow a visitor for its user agent, its claimed name or its verified status (X3). Answer what a request asks for.

1. **Score the live site:** `npx security-pranks-audit@1 <your-domain>`, on Node 22.23.4, 24.22.1 or 26.12.1, or later on the same line. Its requests look like the scanners it checks for (that's the point), so run it only against the project's own site.
   - Exit code 0 means every required check passed, and 1 means at least one failed: read each failing line and its reason. Exit code 2 means it didn't score anything (an unsupported Node version, a bad flag or an unreadable file): fix what the message names and run it again, and don't record a score from it.
   - If a probe gets a 200 or a 5xx (P1), fix that before anything else.
   - If the owner can export a day of request logs (from the host or CDN: combined log format, or JSON lines from Cloudflare, Vercel or Railway), run `npx security-pranks-audit@1 --logs <file>` too. Those are the before numbers (T2). It prints counts only; never paste addresses anywhere. Don't wait for logs to start.
   - No log export (a CDN plan without request log export, or a host that logs only some routes)? On Cloudflare, save the GraphQL Analytics query from [recipes.md](recipes.md#logs-without-a-log-export-cloudflares-analytics-t2) to a file and give that to `--logs`. It needs an API token with read access to analytics, which the owner creates. Its counts are sampled and cover only the top rows, so record them as estimates, with the query's window.

2. **Find where the guard goes.** It has to run before the framework and before any static file, on every path:
   - **Next.js:** `src/proxy.ts` (Next 16) or `src/middleware.ts` (Next 15 and earlier). Don't exclude `_next/image` from the matcher.
   - **Express or another Node server:** the first middleware.
   - **nginx:** a `location` block, with `always` on every `add_header`.
   - **A static site on a host or CDN:** the host's edge middleware or functions (a Cloudflare Worker or Pages Function, Vercel Routing Middleware, Netlify Edge Functions). A rewrite to a static file usually can't set a 404 status and the headers, so check what the host supports.
   - **A site with an API:** exempt the API's prefix (and any MCP endpoint) from the prank. A probe there gets the API's own JSON 404 or 401, which is fine, and the scorecard counts it as the API answering.
   - **A site where users choose URLs** (slugs, usernames, uploaded file names under a prefix such as `/u/` or `/[content]/`): exempt those prefixes too, now. The route test only covers the URLs that exist today, and the next user to pick a name like `env-setup` or `notes.php` would get the prank on their own page (P6).

   Code for the first three is in [recipes.md](recipes.md). If the owner runs several sites, put the pattern and the prank helper in one shared module or package, so a fix reaches all of them.

3. **Make the target smaller (H1, H2, H3).**
   - A read-only site answers anything but `GET` and `HEAD` with 405 and `Allow: GET, HEAD`. A site with forms or an API refuses only the methods each route doesn't use, and makes sure none answers with a 5xx.
   - On Next.js, answer 404 for `/_next/image` if no page uses `next/image`.
   - Pin the runtime version in the repo, on its current security release.

4. **Write the prank, and show it to the owner (C1, C2).** It speaks in the owner's name on a public domain, so get their OK on the wording before it ships.
   - Pick the "only secret": something the project already gives away freely, such as its public meetings, opening hours, source code or published annual report. The table in [STANDARD.md C1](../STANDARD.md#c1-the-only-secret-you-have) has ideas.
   - If `--logs` shows other families reaching the site (actuator and heap dumps, WordPress and PHP, `.git`), give each its own short reply in the same voice, with a link carrying a tag the site's analytics reads (any parameter and value; one per family if you want them apart). Skip any family the site really serves. Count the follows with `--logs <file> --tag <your tag>`.
   - Every value plainly not a credential (P2): no strings shaped like keys, tokens or connection URLs, even fake ones, and no secret-shaped name (`SECRET_KEY`, `DATABASE_PASSWORD`) with a one-word value. `PASSWORD_REQUIRED=false` is fine.
   - If it states facts, build them from the same source the site publishes (P7).
   - Add a note for AI agents that invites the operator, with a link (C2). Never tell the agent to send a request, run a command or register: that's a prompt injection, however friendly.
   - Optionally, put a one-line version of the note in an `X-` header of the site's own naming, on the prank's answers only (C2).
   - The examples in the standard and recipes are placeholders: the wording, names, tags and what the prank offers are the project's own. Match the rules, not the examples, and be creative: write something only this project would say.
   - Keep every probe answer a 4xx, even on a static site with nothing to leak: a 200 is read as "found" whatever the body says (P1).
   - End the note with a link to `/.well-known/security.txt`, and serve that file if the site doesn't yet: a real inbox and an `Expires` under a year ahead ([recipes.md](recipes.md)). Ask the owner which address to use, and never guess or invent one: a researcher's report sent to an inbox nobody reads is lost. If the owner has no address to give, leave out the link and the file. The joke is for scanners; a real researcher needs a way to report.
   - A prank is optional. If the owner doesn't want one, skip this step, record C1 as declined with the reason, and do the rest: the hardening and the rules are what keep the site safe.
   - If the site's ordinary 404 already answers every probe well (a 4xx, plain text with `nosniff`, small, nothing shaped like a credential, the echoed path cleaned and capped, and a line that invites rather than orders), it can be the whole answer. Record C1 as declined with that reason, and keep it ordinary: the scorecard counts an answer as a prank only when it differs from the ordinary 404, and P8 fails a prank that leaks into it.

5. **Add the guard** behind the probe pattern: status 404, `X-Robots-Tag: noindex`, `Content-Type: text/plain`, `X-Content-Type-Options: nosniff`, and `Cache-Control: no-store` or a cache of a day or less (P1, P3, P4). If you echo the path, strip it to printable ASCII and cap its length (P5). Every other missing page keeps the normal 404 (P8). Run the pattern over every real route first, and narrow it if anything matches (P6). Prefixes where users choose the path stay exempt even when every current route passes.

6. **Add the guard tests (T1)** from [recipes.md](recipes.md): probes, an ordinary missing page, methods, the framework endpoint, every real route against the pattern, and quoted facts. Run them against the built server, and watch each fail once with the guard turned off.

7. **Switch over the docs (one commit):**
   - Add the pointer stub from [STANDARD.md §10](../STANDARD.md#10-adopting-the-standard-in-a-repo) to the repo's docs, with the "only secret" and any declined items, each with its reason.
   - Generate the status page: `npx security-pranks-audit@1 --matrix <your-domain> > docs/security-pranks-status.md`. Keep it in the project's private repo when there is one. If the owner runs several sites, one page for all of them lives in whichever repo they use for operations: `--matrix <domain> <domain> ...`.
   - Add one rule to CLAUDE.md or AGENTS.md: after changing middleware, the proxy, routes, the 404 page or the prank, run the guard tests and score the build.

8. **Verify locally:** build and test, then score the local build: `npx security-pranks-audit@1 <your-domain> --base http://localhost:<port>`. On a local or private address (localhost, a loopback or private IP, a single-label name such as a Docker service, or a `.local`, `.internal`, `.test`, `.lan` or `.home.arpa` name) it names your domain as the Host, so a server that runs several sites answers as the one being scored. A public hostname, such as a hosted preview, keeps its own name.

9. **If the site is behind Cloudflare or another CDN (H4),** check that its bot settings match what the owner told you the site welcomes. If it welcomes agents: Bot Fight Mode off, and each AI bot group in the CDN's settings set to Allow (Cloudflare's names for the groups vary, so read them in the dashboard). Optionally propose the edge rule from [recipes.md](recipes.md) for probe families the prank doesn't answer, tested against the sitemap first. If the zone already has a rule keyed on a network (ASN) for another reason, it's the owner's and outside this standard: don't add one for probes (X3), and tell the owner if an existing one covers the API, the MCP endpoint or the discovery files.

10. **Ask the owner, then deploy.** Get the owner's OK before deploying, and before changing CDN, firewall or DNS settings: each is live for every visitor at once. After the deploy, run `npx security-pranks-audit@1 <your-domain> --compare docs/security-pranks-status.md` against production to see what changed, regenerate the status page, and commit. Compare item by item, not just the totals: adding a prank makes P3, P4 and C2 apply.

11. **A day after the deploy,** if you have logs (or the analytics query), run `--logs` on a day of them again. Scanner 5xx should be zero, every probe still a failure, and nothing readers use changed.

When you're done, report the `--compare` output (what changed), the score before and after, the prank text, the `--logs` numbers before and after if you had logs, and anything you declined.

## Lessons from the sites that switched over

- On the playbook's sites, refusing unused methods turned framework 500s with stack traces into clean 405s. Fake Next.js Server Action POSTs are the usual source.
- The first image-endpoint check asked for a missing local file, and the live optimizer also answered that with 404, so the check passed with or without the fix. Ask for a remote URL, which the live optimizer rejects with 400.
- The playbook's pattern catches any path where `env` is followed by `-`, `.`, `_`, `:` or `/`. A route like `/meetings/env-council` would get the prank. Run the route test before you ship.
- A CDN's managed firewall rules may block some probes (Cloudflare blocks `/wp-config.php` on upstateny.news) before your guard sees them. That's a safe 403, and the scorecard reports it as blocked at the edge rather than grading it as the prank.
- nginx drops `add_header` on error responses unless you add `always`.
- At animalhouse (an app with an API), a pet named "Ugly.php" would have lost its page to the `.php` reply. Exempting the real content prefixes fixed it. Its test builds every route from the app's route folders, with sample names that hold dots, and checks each against the pattern; the 715 sitemap URLs were checked once by script.
- The same site exempted its prefixes after lowercasing the path, so `/API/.ENV` counted as the API and got the ordinary HTML 404, because the routes are case-sensitive and the API never saw it. Compare prefixes with the path as it came, and lowercase only for the pattern ([recipes.md](recipes.md)).
- Its first guard returned the prank from the Next.js proxy before the proxy's own security headers were set, so the prank had no `nosniff` and failed P4 while every page passed. Set the prank's headers on its own response.
- On a site with an API, `--logs` used to count every POST as an unused method: 1,924 successful API calls showed up as "probes that got a 2xx". It now counts a method only on a path that never succeeded with it in the log.
- animalhouse's first draft named its jokes `DATABASE_PASSWORD=feed-the-ferret-first` and told agents to `POST` to the sign-up API. Both read as jokes to a person. The first trips generic secret scanners (P2), and the second only works as a prompt injection (C2). The scorecard warns on both.
- Keep logs somewhere a deploy can't wipe them, or there's nothing to compare after.
