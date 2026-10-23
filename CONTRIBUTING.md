# Contributing

The standard gets better when a project finds a better practice, or a mistake, and sends it back. Issues and pull requests are welcome.

## What belongs in the standard

- **Most small public sites should do it.** A practice that suits one project goes in "Considered and left out" (§9), with the reason.
- **It names the harm it prevents.** Required items prevent harm to the site, to a stranger, or to readers. A rule that only feels safe doesn't belong.
- **It rests on evidence:** request logs, a measured before and after, or a primary source (an RFC or official documentation) cited in §12 with a date.

## Changing a check

1. Describe the item in STANDARD.md first: its ID, level, why, "done when" and what the scorecard does, plus its row in the checklist (§11). The tests fail if the scorecard runs a check the checklist doesn't list, at a different level, or if a checklist item says "score" and isn't scored.
2. Implement it in `src/audit.mjs`, with any logic worth testing on its own as a pure function in `src/helpers.mjs` (tested in `test/helpers.test.mjs`). The audit requests only the named site; every request goes through `get()`, which calls `request()` in `src/http.mjs`, never `fetch`. No dependencies, Node 26 or later.
3. Add a case to both fixture sites in `test/fixture-site.mjs`: the good site passes it, the broken site fails it for a reason you assert in `test/audit.test.mjs`. Watch the assertion fail before you make it pass.
4. Run `npm test`, then run the CLI against two or three sites you run and read the output for false results.
5. Add a CHANGELOG entry. A new required check, or a stricter one, is a major version, because projects pin a major version (`security-pranks-audit@1`).

Never put a credential-shaped string in the repo, even a fake one: build test samples at run time.

## Writing

Plain, direct sentences. Say what to do and why. No em dashes.
