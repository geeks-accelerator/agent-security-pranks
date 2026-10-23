# Adopting the standard: instructions for a project's agent

To switch a project over, give its coding agent one line:

> Adopt the Agent Security Pranks Standard in this repo by following https://github.com/geeks-accelerator/agent-security-pranks/blob/main/docs/adopting.md

Everything below is for that agent. The lessons at the end come from the sites that switched over first.

1. **Score the live site:** `npx security-pranks-audit@1 <your-domain>`, on Node 26 or later. Its requests look like the scanners it checks for (that's the point), so run it only against the project's own site. Exit code 1 means a required check failed. Most sites start with H1 or H2 failing and no prank (C1); a site that answers a probe with a 200 or a 5xx (P1) fixes that first.
   - If the owner can export a day of request logs (from the host or CDN: combined log format, or JSON lines from Cloudflare, Vercel or Railway), run `npx security-pranks-audit@1 --logs <file>` too. Those are the before numbers (T2). It prints counts only; never paste addresses anywhere. Don't wait for logs to start.

2. **Find where the guard goes.** It has to run before the framework and before any static file, on every path:
   - **Next.js:** `src/proxy.ts` (Next 16) or `src/middleware.ts` (Next 15 and earlier). Don't exclude `_next/image` from the matcher.
   - **Express or another Node server:** the first middleware.
   - **nginx:** a `location` block, with `always` on every `add_header`.
   - **A static site on a host or CDN:** the host's edge middleware or functions (a Cloudflare Worker or Pages Function, Vercel Routing Middleware, Netlify Edge Functions). A rewrite to a static file usually can't set a 404 status and the headers, so check what the host supports.

   Code for the first three is in [recipes.md](recipes.md). If the owner runs several sites, put the pattern and the prank helper in one shared module or package, so a fix reaches all of them.

3. **Make the target smaller (H1, H2, H3).**
   - A read-only site answers anything but `GET` and `HEAD` with 405 and `Allow: GET, HEAD`. A site with forms or an API refuses only the methods each route doesn't use, and makes sure none answers with a 5xx.
   - On Next.js, answer 404 for `/_next/image` if no page uses `next/image`.
   - Pin the runtime version in the repo, on its current security release.

4. **Write the prank, and show it to the owner (C1, C2).** It speaks in the owner's name on a public domain, so get their OK on the wording before it ships.
   - Pick the "only secret": something the project already gives away freely, such as its public meetings, opening hours, source code or published annual report. The table in [STANDARD.md C1](../STANDARD.md#c1-the-only-secret-you-have) has ideas.
   - Every value plainly not a credential (P2): no strings shaped like keys, tokens or connection URLs, even fake ones.
   - If it states facts, build them from the same source the site publishes (P7).
   - Add a note for AI agents that asks nothing harmful (C2).
   - A prank is optional. If the owner doesn't want one, skip this step, record C1 as declined with the reason, and do the rest: the hardening and the rules are what keep the site safe.

5. **Add the guard** behind the probe pattern: status 404, `Cache-Control: no-store`, `X-Robots-Tag: noindex`, `Content-Type: text/plain` and `X-Content-Type-Options: nosniff` (P1, P3, P4). If you echo the path, strip it to printable ASCII and cap its length (P5). Every other missing page keeps the normal 404 (P8). Run the pattern over every real route first, and narrow it if anything matches (P6).

6. **Add the guard tests (T1)** from [recipes.md](recipes.md): probes, an ordinary missing page, methods, the framework endpoint, every real route against the pattern, and quoted facts. Run them against the built server, and watch each fail once with the guard turned off.

7. **Switch over the docs (one commit):**
   - Add the pointer stub from [STANDARD.md §10](../STANDARD.md#10-adopting-the-standard-in-a-repo) to the repo's docs, with the "only secret" and any declined items, each with its reason.
   - Generate the status page: `npx security-pranks-audit@1 --matrix <your-domain> > docs/security-pranks-status.md`. Keep it in the project's private repo when there is one. If the owner runs several sites, one page for all of them lives in whichever repo they use for operations: `--matrix <domain> <domain> ...`.
   - Add one rule to CLAUDE.md or AGENTS.md: after changing middleware, the proxy, routes, the 404 page or the prank, run the guard tests and score the build.

8. **Verify and ship:** build and test, and score the local build before you deploy: `npx security-pranks-audit@1 <your-domain> --base http://localhost:<port>`. After the deploy, run `npx security-pranks-audit@1 <your-domain> --compare docs/security-pranks-status.md` against production to see what changed, regenerate the status page, and commit. Compare item by item, not just the totals: adding a prank makes P3, P4 and C2 apply.

9. **Ask the owner before deploying,** and before changing CDN, firewall or DNS settings. Each is live for every visitor at once.

10. **A day after the deploy,** if you have logs, run `--logs` on a day of them again. Scanner 5xx should be zero, every probe still a failure, and nothing readers use changed.

When you're done, report the `--compare` output (what changed), the score before and after, the prank text, the `--logs` numbers before and after if you had logs, and anything you declined.

## Lessons from the sites that switched over

- On the playbook's sites, refusing unused methods turned framework 500s with stack traces into clean 405s. Fake Next.js Server Action POSTs are the usual source.
- The first image-endpoint check asked for a missing local file, and the live optimizer also answered that with 404, so the check passed with or without the fix. Ask for a remote URL, which the live optimizer rejects with 400.
- The playbook's pattern catches any path where `env` is followed by `-`, `.`, `_`, `:` or `/`. A route like `/meetings/env-council` would get the prank. Run the route test before you ship.
- A CDN's managed firewall rules may block some probes (Cloudflare blocks `/wp-config.php` on upstateny.news) before your guard sees them. That's a safe 403, and the scorecard reports it as blocked at the edge rather than grading it as the prank.
- nginx drops `add_header` on error responses unless you add `always`.
- Keep logs somewhere a deploy can't wipe them, or there's nothing to compare after.
