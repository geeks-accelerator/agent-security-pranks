# Adopting the standard: instructions for a project's agent

To switch a project over, give its coding agent one line:

> Adopt the Agent Security Pranks Standard in this repo by following https://github.com/geeks-accelerator/agent-security-pranks/blob/main/docs/adopting.md

Everything below is for that agent.

1. **Measure first.** Ask the owner for a day of request logs (an export from the host or CDN: combined log format, or JSON lines from Cloudflare, Vercel or Railway), then run `npx security-pranks-audit@1 --logs <file>`. Note the probe count, the 404 share, and any probe that got a 2xx or a 5xx. Those are your before numbers (T2). It prints counts only; don't paste addresses anywhere.

2. **Score the live site:** `npx security-pranks-audit@1 <your-domain>`, on Node 26 or later. It requests only that site, and its requests look like scanners, so run it only against the project's own site. Exit code 1 means a required check failed.

3. **Make the target smaller (H1, H2, H3).** In middleware or the proxy, before the framework:
   - A read-only site answers anything but `GET` and `HEAD` with 405 and `Allow: GET, HEAD`. A site with forms or an API refuses only the methods it doesn't use, per route, and makes sure none of them answers with a 5xx.
   - On Next.js, answer 404 for `/_next/image` if no page uses `next/image`, and don't exclude it from the middleware matcher.
   - Pin the runtime version in the repo to its current security release.

4. **Pick the "only secret" (C1).** Something the project already gives away freely: its public meetings, its opening hours, its source code, its published annual report. Ask the owner if it isn't obvious. Every value must be plainly not a credential (P2). If it states facts, build them from the same source the site publishes (P7). Add a note for AI agents that asks nothing harmful (C2).

5. **Add the prank** behind the probe pattern, with status 404, `Cache-Control: no-store`, `X-Robots-Tag: noindex`, `Content-Type: text/plain` and `X-Content-Type-Options: nosniff` (P1, P3, P4). If you echo the path, strip it to printable ASCII and cap it (P5). Leave every other 404 alone (P8). Code for Next.js, Express and nginx: [recipes.md](recipes.md).

6. **Add the guard tests (T1)** from [recipes.md](recipes.md): probes, an ordinary missing page, methods, the framework endpoint, every real route against the pattern (P6), and quoted facts (P7). Run them against the built server, and watch each fail once with the guard turned off.

7. **Score the build before you deploy:** `npx security-pranks-audit@1 <your-domain> --base http://localhost:<port>`. Fix every required failure.

8. **Switch over the docs (one commit):**
   - Add the pointer stub from [STANDARD.md §10](../STANDARD.md#10-adopting-the-standard-in-a-repo) to the repo's docs, with your "only secret" and any declined items.
   - Add one rule to CLAUDE.md or AGENTS.md: after changing middleware, the proxy, routes or the 404 page, run the guard tests and score the build.

9. **Ask the owner before deploying,** and before changing CDN or firewall settings: both are live for every visitor.

10. **After the deploy,** score production, then measure a day of logs again with `--logs`. Scanner 5xx should be zero, every probe still a failure, and nothing readers use changed.

When you're done, report the before and after `--logs` numbers, the score before and after, the prank text, and anything you declined.

## Lessons

- On the playbook's sites, refusing unused methods turned framework 500s with stack traces into clean 405s. Fake Next.js Server Action POSTs are the usual source.
- The first image-endpoint check asked for a missing local file, and the live optimizer also answered that with 404, so the check passed with or without the fix. Ask for a remote URL, which the live optimizer rejects with 400.
- nginx drops `add_header` on error responses unless you add `always`.
- The playbook's pattern catches any path where `env` is followed by `-`, `.`, `_`, `:` or `/`. A route like `/meetings/env-council` would get the prank. Run the route test before you ship.
- A CDN's managed firewall rules may block some probes (Cloudflare blocks `/wp-config.php` on some plans) before your prank sees them. That's a safe 403, and the scorecard reports it as blocked at the edge rather than grading it as the prank.
