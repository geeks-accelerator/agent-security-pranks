# Reviews from AI models

On 2026-10-24 we asked five AI models, each in a fresh chat, to read this repo and review it honestly, criticism welcome. Each read the repo through its own web access; the files it says it read are listed under its review.

These are excerpts in the models' own words. Cuts are marked [...]. We left out remarks about the repo's age, star count, commit history and the independence of its evidence (the research covers one owner's sites, as it says), and kept the criticism of the standard and the tool. [What we changed](#what-we-changed) lists what we did about it. Where a review gets a fact wrong, a note follows it.

The prompt:

> Please read this GitHub project and write an honest review of it in the first person, 150 to 250 words: https://github.com/geeks-accelerator/agent-security-pranks (start with README.md, then STANDARD.md and docs/research/). Say what you find useful, what's weak, missing or questionable, and whether you'd recommend it and to whom. Criticism is welcome; please don't flatter. At the end, list which files you actually read. The authors may quote your review word for word, with your model name and today's date.

The reviews are of version 1.2.7.

## Grok 4.7 (grok.com)

The practical core is solid. Small sites really do see a lot of secret-hunting probes, the numbers from the Cloudflare week and the civic-guide logs make that concrete, and answering with a clean 4xx instead of a 200-plus-fake-keys is the right call. Honeypots that return credential-shaped strings put the domain on other people’s target lists; this standard and its scorecard explicitly forbid that. The zero-dependency CLI that probes the same paths scanners hit, checks status codes, headers, and absence of credential shapes, and can also parse logs is the useful part. Refusing unused methods and framework endpoints first is the actual hardening; a site with no joke at all can still pass the required checks. That framing is clearer than most “block the bots” advice.

What’s weaker is the prank itself. The authors’ own survey notes that most scanners read the status and move on, so the friendly note for AI agents is mostly theater for the human operator who later looks at a report. [...] the Node version pins feel fussy for a tool with no dependencies. [...]

I’d recommend the audit and the required rules to anyone running a small static, news, or Next.js site who is tired of probe noise and wants a measurable, agent-friendly refusal without traps. I would not treat the optional prank as security, and larger setups with a real WAF already covering the same ground can skip it.

*Files read: README.md, STANDARD.md, docs/research/bots-in-ai-clothing.md, docs/research/who-else-talks-to-scanners.md.*

## GPT-6 Astra Pro (chatgpt.com)

I’d recommend Agent Security Pranks to maintainers of small public websites as a focused hardening and regression checklist. I find the concrete rules useful: refuse unused methods, return proper error responses, avoid fake credentials, preserve legitimate routes, and demonstrate that tests fail when safeguards are removed. Making the prank optional is a sensible decision.

I’m less convinced by the evidence for the jokes and agent invitations. [...] I found no controlled comparison showing what the prank adds over an ordinary 404, or measured follow-through from its invitations.

I also think the README’s “can’t backfire” promise overreaches. A handful of probe requests and sampled sitemap pages cannot establish that, even though the documentation acknowledges its limits. The claimed Next.js image-optimizer vulnerability also needs an identifiable advisory citation; the standard explicitly leaves that for later.

I would use the checklist to catch specific deployment mistakes and treat the humor as an experiment. I would not treat a passing score as evidence that a site is secure. My recommendation is based on reading the documentation and research; I did not run the CLI.

*Files read: README.md, STANDARD.md, docs/research/bots-in-ai-clothing.md, docs/research/who-else-talks-to-scanners.md, docs/research/bots-in-ai-clothing/data.json, docs/scanner-prank-playbook.md.*

## Kimi K3 (OpenRouter)

What's genuinely useful: the hardening core — refusing unused methods and framework endpoints (H1/H2) — is cheap, sound advice; the case against honeypots (a 200 plus fake credentials lands you on target lists and sends third parties chasing false alarms) is well argued; and bots-in-ai-clothing (448k probes, zero from verified AI crawlers, one scanner rotating twenty AI names) is a neat empirical argument against user-agent-based blocking. A zero-dependency audit with CI exit codes and log analysis is practical.

What's weak: [...] The prank premise is thin: the project's own research says bots read status codes and move on, so C1/C2 address an audience that mostly isn't there, and C2's "orders" detector is brittle pattern matching. H2 covers only Next.js; P6's ten-page sitemap sample is weak assurance. [...]

I'd recommend it to owners of small Next.js/static sites on Cloudflare, for the audit and the H/P/X rules, with the joke as optional garnish. I wouldn't treat a 10/10 score as security assurance.

*Files read: README.md, STANDARD.md, docs/research/bots-in-ai-clothing.md, docs/research/who-else-talks-to-scanners.md.*

## DeepSeek V4 Pro (OpenRouter)

I came in skeptical and left mostly convinced, with real reservations. The genuinely good idea here is the reframing: instead of blocking "AI bots" by user agent (which their own traffic data shows is futile — the biggest scanner rotated through ~20 fake crawler names) or running 200-status honeypots (which put you on "found something" lists), answer probes with a 4xx plus a joke in your own voice. The hardening bits — refusing unused HTTP methods (H1) and the always-on /_next/image endpoint (H2) — are the most valuable part, and the "no credential-shaped strings, even fake" rule (P2) is a genuinely sharp insight most honeypot authors miss.

What's actually good: the standard is unusually rigorous. Every rule names a harm it prevents, every check is designed to be able to fail (they document catching a test that could never fail), and the security-pranks-audit CLI is real, zero-dependency code that gates CI and even decodes gzip itself. The research docs are honest about method limits (sampled Cloudflare counts, conservative patterns). The security.txt door for real researchers and the "invite the operator, never order the agent" (C2) rule show thoughtful restraint rather than injection-bait.

[...] The docs are long and repetitive — README, STANDARD, playbook, adopting guide, recipes all restate the same rules — and the audit can't verify most of what it claims to keep you safe (route coverage, facts in jokes, runtime pinning are all "review/test").

Would I recommend it? The standard — yes, as a checklist of genuinely good hygiene for small-site operators, particularly the method/endpoint refusal and the "never fake a credential" rule. The tooling is competently built. [...] Worth a read for anyone running small sites that get hammered by scanners.

*Files read: README.md, STANDARD.md, docs/research/bots-in-ai-clothing.md, docs/research/who-else-talks-to-scanners.md, docs/scanner-prank-playbook.md, docs/adopting.md, bin/security-pranks-audit.mjs, src/audit.mjs.*

## Gemini 4 Argon (OpenRouter)

agent-security-pranks packages a quirky idea—serving harmless jokes on vulnerability probe paths like /.env and /.git/config—into a surprisingly pragmatic web hardening standard and zero-dependency CLI auditor (security-pranks-audit).

What I find most useful is that the prank is secondary to real security hygiene. The empirical data in docs/research/ (analyzing 448,000 probes across 56 domains) smartly proves that blocking "AI bots" by User-Agent is futile because scanners spoof them, while returning 200 OK with fake keys or prompt injections (honeypots) only lands your domain on shared target lists and triggers false alarms. Requiring strict 4xx responses, text/plain with nosniff, 405 on unused HTTP methods, and disabling unused framework endpoints like Next.js's /_next/image (which turned scanner-triggered 500s into clean refusals) provides immediate value even if you skip the joke entirely. The --logs and --matrix CLI modes are also great additions for multi-site CI gating.

What is weak or questionable: the CLI (bin/security-pranks-audit.mjs) hard-exits unless you run a bleeding-edge Node security release (22.23.4, 24.22.1, or 26.12.1+), creating major friction in standard CI environments. Furthermore, H2 only checks Next.js rather than other frameworks' exposed endpoints, and the core premise of C2 (leaving polite notes for LLM scanners) is admittedly aspirational since the authors' own logs show probes are still overwhelmingly dumb scripts that ignore response bodies.

I recommend this to indie developers and small-site operators who want lightweight, agent-friendly edge hardening—and a bit of safe fun in their logs—without blocking legitimate AI crawlers.

*Files read: README.md, STANDARD.md, docs/research/bots-in-ai-clothing.md, docs/research/who-else-talks-to-scanners.md, bin/security-pranks-audit.mjs.*

*Note: on the playbook's sites, the 500s that became clean refusals came from refusing unused methods (H1), not from closing `/_next/image` (H2). Gemini's own app (gemini.google.com) couldn't open URLs, so this review came through OpenRouter.*

## What we changed

In version 1.2.8, from these reviews:

- **"Can't backfire" overreached** (GPT-6 Astra Pro). The README now calls it guardrails: the audit catches the common ways a joke hurts someone, from the probes it sends and a sample of pages, and the guard tests cover your routes (T1).
- **The image-optimizer advisory needed a citation** (GPT-6 Astra Pro). STANDARD.md now cites them: seven advisories for `/_next/image` in 2026, two of them critical remote code execution (GHSA-2xp9-vwfh-vxw4 and GHSA-2464-fhr4-w9xw).
- **H2 covers only Next.js** (Kimi K3, Gemini 4 Argon). H2 now says it applies to any framework with an always-on endpoint, and the README says Next.js is the only one the audit knows so far, so on another framework it's yours to review.
- **The order detector is brittle** (Kimi K3). STANDARD.md and the README now say it's a heuristic: it warns rather than fails, can miss an order phrased another way, and the note is yours to read.
- **The Node pins feel fussy** (Grok 4.7, Gemini 4 Argon). The README now says why (the audit reads answers from sites it doesn't control, and the 2026-10-21 releases fixed a decoder bug and TLS hostname checks), and the error on an older Node says how to update.

Left as they are, with the reason:

- **The prank mostly reaches people, not scanners** (all five). We agree, and C1 says so: expect a trickle of follow-through from scanners and a larger audience reading scan reports. The prank stays optional, and a site with none passes every required check.
- **No controlled comparison of a prank against a plain 404** (GPT-6 Astra Pro). True so far. `--logs --tag` is how a site measures follow-through, and we'll add results to the research when we have them.
- **The docs repeat each other** (DeepSeek V4 Pro). Each is written for a different reader (the README for people deciding, STANDARD.md for the rules, the adopting guide for a coding agent, the recipes for code), so some overlap is on purpose.
