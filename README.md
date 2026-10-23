# Agent Security Pranks

[![CI](https://github.com/geeks-accelerator/agent-security-pranks/actions/workflows/ci.yml/badge.svg)](https://github.com/geeks-accelerator/agent-security-pranks/actions/workflows/ci.yml)

Check that your site answers `.env`, `.git` and other secret-hunting probes safely, and, if you like, with a joke.

Most of the traffic on a small public site is bots and agents hunting for leaked secrets: `/.env` in every variation, `/.git/config`, SSH keys, `/.aws/credentials`, `wp-config.php`. You can refuse what your site never needs, and answer the rest with a prank that costs nothing, leaks nothing and can't be mistaken for a find. This repo holds:

- **[STANDARD.md](STANDARD.md):** the Agent Security Pranks Standard. What to do, item by item, each with an ID, a level and the harm it prevents: hardening (H), prank rules (P), things never to do (X), what to serve (C), and tests and measurement (T).
- **`security-pranks-audit`:** a command-line scorecard that probes a live site the way scanners do and checks every answer against the standard.
- **[The Scanner Prank Playbook](docs/scanner-prank-playbook.md):** the field guide the standard comes from, with the measurements, the menu of pranks and code for Next.js, Express and nginx.

## Score a site

```
npx security-pranks-audit example.com
```

It needs Node 26 or later, with current security releases, and has no dependencies. It sends about 20 requests, a few at a time: eight probe paths, an echo test, a missing page, `GET` and `HEAD /`, an empty `POST` and `PUT /` that create nothing, the framework endpoint it detects, and up to 10 sitemap pages. It only requests the site you name (and its www or bare twin), and never follows a redirect off it. It caps every answer at 256 KB, before and after decoding, and 10 seconds, so a site that answers with a zip bomb or a tarpit can't hurt the machine running it. It prints a pass, warning or failure for each check, with the reason, and exits with code 1 when a required check fails, so it can gate a deploy.

**Run it only against sites you run.** Its requests look like the scanners it checks for, in your logs and to a firewall. It names itself in its user agent (`security-pranks-audit/<version> (+repo URL)`) so you can tell its requests apart.

```
security-pranks-audit <domain> [--json] [--compare previous] [--base url]
security-pranks-audit --matrix <domain> <domain> ... [--compare previous]
security-pranks-audit --logs <access-log> [--json]
```

| Option | What it does |
|---|---|
| `--json` | print the results as JSON |
| `--base url` | score a local or preview build as the domain before you deploy (`--base http://localhost:3000`) |
| `--compare file` | list what changed since a previous run: a status page from `--matrix` or a saved `--json` report |
| `--matrix` | score several sites, a few at a time, and print one markdown status page |
| `--logs file` | count secret-hunting probes in an exported access log (combined log format, or JSON lines from Cloudflare, Vercel or Railway) by kind, status and client family, and list any probe that got a 2xx or a 5xx. It prints counts, never addresses |

From a clone, run `node bin/security-pranks-audit.mjs example.com`.

## Score all your sites

`--matrix` is built for a network of sites: one run, one status page with a column per site and a "what to fix" list for each.

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
- no answer contains anything shaped like a credential (P2);
- the prank sends `no-store` and `noindex`, stays out of the sitemap, and is `text/plain` with `nosniff` (P3, P4);
- an echoed path comes back cleaned (P5);
- sitemap pages and an ordinary missing page never get the prank (P6, P8);
- unused methods get a 405 with `Allow`, and reads still work (H1);
- Next.js's `/_next/image` answers 404 when no page uses it (H2);
- every answer is small, prompt and stays on the site: no zip bombs, tarpits or redirects to someone else (X1);
- whether there's a prank at all, and a note in it for AI agents (C1, C2).

It works out what applies: it detects the framework from the homepage, the prank from the probe answers and an echo from a marker in the path, and skips what doesn't apply with the reason.

It can't see your routes beyond the sitemap, whether the facts in your prank are right, your runtime version, or whether your tests have ever failed. The standard marks those "test" or "review", and [docs/recipes.md](docs/recipes.md) has guard tests for them.

## Use it in your project

Point to [STANDARD.md](STANDARD.md) from your repo instead of copying it (§10 has a short stub), and pin the scorecard to a major version: `npx security-pranks-audit@1 <domain>`.

To switch a project over, point its coding agent at [docs/adopting.md](docs/adopting.md).

## Related

[agent-and-search-readiness](https://github.com/geeks-accelerator/agent-and-search-readiness) and its scorecard [`readiness-audit`](https://www.npmjs.com/package/readiness-audit) do the same for making a site findable and usable by AI agents and search engines. This repo follows its shape: a standard with IDs and levels, and a read-only, zero-dependency scorecard.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a security problem, see [SECURITY.md](SECURITY.md).

## License

MIT
