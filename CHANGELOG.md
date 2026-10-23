# Changelog

## 1.0.0 (unreleased)

The first release: the Agent Security Pranks Standard and its scorecard, built from the Scanner Prank Playbook.

- **STANDARD.md:** 18 items in five families: hardening (H1 to H3), prank rules (P1 to P8), never (X1, X2), what to serve (C1 to C3), and tests and measurement (T1, T2). Each has a level, the harm it prevents, a "done when" and a checklist row. Sources in §12.
- **`security-pranks-audit <domain>`:** 12 checks from outside (P1 to P6, P8, H1, H2, X1, C1, C2), in about 20 requests plus up to 10 sitemap pages. It detects the framework, the prank and an echoed path, and skips what doesn't apply. It requests only the named site, never follows a redirect off it, and caps every answer at 256 KB and 10 seconds. Exits 1 on a required failure.
- **`--matrix`** scores several sites, three at a time, into one status page; **`--compare`** lists what changed since a saved page or JSON report; **`--base`** scores a local or preview build.
- **`--logs`** counts secret-hunting probes in an exported access log by kind, status and client family, and lists probes that got a 2xx or a 5xx. Counts only, never addresses.
- Needs Node 26.12.1 or later; the CLI exits with a message on an older version.
