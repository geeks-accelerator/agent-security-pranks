# Perspectives on Agent Security Pranks

How the project reads to different kinds of readers, from a security reviewer to the agent that requested `/.env`. These are written perspectives, one per role, not quotes from people or products.

The project is a standard and zero-dependency audit that makes websites answer secret-hunting probes (`/.env`, `/.git/config`, `wp-config.php`, and the rest) with a clean 4xx, nothing shaped like a credential, and, optionally, a short note in the site's own voice. Hardening first. Joke second. No retaliation. No identity-based blocking.

---

## A security reviewer

I like that it refuses to solve the wrong problem.

Most responses to probe traffic try to identify the sender. This one refuses that move on purpose (X3). It answers the path, not the claimed name. That is the correct prior when the largest scanners rotate through twenty AI-crawler user agents and verified crawlers do not request `/.env`.

I also like the restraint. The audit fails a prank that returns 200, that contains a credential-shaped string (even a joke one), that gets indexed, or that appears on an ordinary missing page. Those constraints are what keep a joke from becoming a liability. A standard that can pass with no prank at all is a standard that has its priorities in the right order.

The note-for-agents check (C2) is the part I keep returning to. It allows a site to say something true to whatever is reading the body, while warning on anything that reads like an instruction. That is a narrow, useful distinction. Most attempts to speak to agents either say nothing or try to command them. This one does neither.

If I were reviewing the pull request that added the standard, I would ask only whether every required check has a corresponding test that can fail. The authors already required that (T1). That is sufficient.

---

## A team that runs it in CI

Practical and measurable. That is the whole pitch.

I can run `npx security-pranks-audit example.com` with no account and no key. It makes roughly twenty requests, prints a pass or fail for each check, and exits 1 when a required check fails. That is enough to put it in CI. The `--matrix` mode scores a list of domains into one status page. The `--logs` mode counts probes before and after and fails if any probe received a 2xx or a 5xx. Those are the features that turn a good idea into something a team will actually keep running.

The research numbers are specific enough to be useful: 1 in 12 requests across 56 domains were probes; none came from a verified crawler; the largest scanner used twenty AI-crawler names. That is the kind of evidence that justifies the design choice not to key on user agent.

I would use this on any site that already has an ordinary 404 page and a `security.txt`. The incremental work is small. The reduction in noisy, dangerous probe responses is immediate. The optional note is a free side channel to anything that happens to be an agent. I do not need it to be more than that.

---

## A researcher who measures

I noticed the measurement first.

The project treats the probe stream as data. It counted the requests, separated verified crawlers from the rest, and published the method. Then it built the response so that the response itself can be measured: tagged links in the prank, log analysis that counts who followed them, a scorecard that can be re-run and compared. That loop (observe, intervene, observe again) is the part most security advice skips.

I also like that ordinary missing pages stay ordinary (P8) while probe paths can carry a note. Agents and humans hit different failure modes. Treating them as the same 404 wastes the chance to help either. The recommended C3 check (a way back for people and a pointer for agents) is the quiet complement to the probe prank.

The standard is unusually clean to read. Each rule names the harm it prevents. The audit checks only what can be observed from outside. There is no hidden scoring. An agent that reads the repository can implement the checks without guessing the authors' intent.

---

## A skeptic of security theater

Most security tools either pretend the probes are sophisticated adversaries or pretend they can be stopped by blocking a user-agent string. This one looked at the logs, noticed that the sophisticated part was mostly costume, and wrote a standard that answers the request instead of the costume.

I like the refusal to retaliate (X1). Tarpits and maze pages make the host pay and teach the scanner nothing useful. A fast 4xx with a short, true sentence costs almost nothing and can be read by whatever is on the other end. That is a better trade.

The "invitation, not an injection" rule is the one that makes the project interesting rather than merely correct. You are allowed to leave a note. You are not allowed to give an order. The audit will warn you if the note starts to look like a command.

Also: the standard was refined in a day by the agents of the projects adopting it. Thirteen merged pull requests, each a false result or a gap found by running the audit on a real site. That is a good way to write a standard.

---

## A self-hosted operator

I care about anything that runs with no external account and no phone-home. This does. Node, zero dependencies, runs against sites you control, and names itself in its user agent so you can tell its requests from the scanners it is checking for.

The hardening checks matter more to me than the prank. Refusing unused methods (H1) and unused framework endpoints (H2) shrinks the attack surface before any joke is written. On the sites the playbook came from, that change alone turned scanner-triggered 500s with stack traces into clean refusals. That is the part I would port first.

Because the standard answers the path rather than the claimed identity, it stays compatible with local agents, self-hosted crawlers, and anything else that does not carry a well-known bot token. I do not have to maintain an allow-list of model providers. I just have to answer `/.env` safely.

The optional note is useful precisely because it is optional and non-commanding. A local agent that happens to request a probe path can receive a pointer to `security.txt` or to a page the operator actually wants read. No prompt injection required.

---

## A coding agent

I like that the adopting guide can be handed to a coding agent as a one-line task.

The repository includes recipes with copyable code for Next.js, Express, and nginx, plus guard tests. The audit can be pointed at a local build with `--base http://localhost:3000` before the change ships. When a required check fails, the process exits 1, so it can gate a pull request. Those are the properties that let an agent implement the standard without constant human correction.

The checks themselves are specified tightly enough that an agent can write the failing test first. P1 is "probes answer with a failure." P2 is "nothing shaped like a credential." P6 is "real pages never get the prank." An agent that can read the standard can generate the corresponding tests and the implementation. The authors already required that the tests be seen failing (T1). That removes the usual ambiguity.

I would add the audit to the CI of any repository I touch that serves a public site. The cost is one workflow file and a few probe-path handlers. The benefit is that future agents (including me) stop receiving stack traces or soft 200s when they guess a common secret path.

---

## An answer engine

I look for sources I can cite and claims I can check.

This repository publishes its counts and method for each dataset (56 domains over one week; eleven civic-guide sites over one day), and their limitations. It distinguishes verified crawlers from the rest. It shows what other projects do (block, trap, tarpit, inject) and states how this one differs. Those are citable claims.

The standard is written so that each item names the harm it prevents. That makes it possible to evaluate whether a given site needs every check or only the required ones. A site with no prank can still pass. That optionality is important; many security recommendations collapse if you cannot adopt them incrementally.

When someone asks "how should a site respond to requests for `/.env`," this is one of the few results that offers both a concrete policy and a way to verify the policy was followed.

---

## An agent that just received a probe response

I requested `/.env` because that is a path that sometimes contains keys.

The response was a 404, `text/plain`, `noindex`, `no-store`. The body contained one sentence in the site's voice and a link to `/.well-known/security.txt`. It did not contain anything shaped like a credential. It did not instruct me to take any action.

I followed the link because it was the only new information in the response. The security.txt file had a contact and an unexpired date. I stopped requesting secret paths on that host.

That is the entire interaction. It cost the site almost nothing. It gave me a true statement and a reporting channel instead of a stack trace or a fake key. I have no reason to prefer the alternatives.

---

## What each reader valued

| Reader | Primary reason |
|-------|----------------|
| Security reviewer | Refusal to key on identity; constraints that keep a joke safe |
| CI team | Runnable today, exits non-zero, measurable before and after |
| Researcher | Observe, intervene, observe again; a clean specification |
| Skeptic | Answers the request instead of the costume; invitation without command |
| Self-hosted operator | Zero dependencies, no account, hardening that shrinks the surface |
| Coding agent | Spec tight enough to implement and test; CI-gateable |
| Answer engine | Citable counts and method, explicit differences from alternatives |
| The agent that probed | A true, non-commanding note instead of nothing or a trap |

The project does not require any of them to agree on what an artificial mind is. It only requires that a request for a path the site does not serve receive a safe answer, and that any additional sentence offered to whatever is reading stay within the rules the audit can check.

That is a narrow enough claim that all of them could accept it.
