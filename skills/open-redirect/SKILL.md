---
name: open-redirect
description: >-
  Hunt open redirects on an AUTHORIZED target, from recon through chaining to a
  report. Trigger when the user gives a domain/URL and asks to find open
  redirect / URL redirection, or to run open_redirect.py. Enforces a scope file
  and leaves exploitation and PoC confirmation to the human.
---

# open-redirect

Find parameters that redirect a user to an attacker-controlled host. Open
redirect is low on its own but a strong chain primitive (OAuth/SSO token theft,
phishing, SSRF). Uses `open_redirect.py`, which shares the crlf-hunter recon,
scope (allow/deny), and triage/report core.

## Hard rules
1. **Authorization + scope.** Every host must be in `scope.txt` (allow lines,
   `!` exclusions). The tool refuses anything out of scope.
2. **Detect, don't weaponize.** It confirms the redirect to a canary; it never
   sends a real victim anywhere.
3. **Confirm by hand.** Follow the redirect in a browser before reporting. A
   same-host or self-referential redirect is **not** a bug.

## Run
```bash
# use a canary host you control for the cleanest PoC (else defaults to example.com)
python3 open_redirect.py -d "*.target.com" --scope scope.txt --canary your-canary.com \
    --llm --llm-provider claude-code --no-crawl
python3 open_redirect.py -u https://app.target.com/go?next=x --scope scope.txt
```
Output in `openredirect_<target>/`: `findings.json`, `triage.json`,
`report_openredirect.md`.

## What counts as a hit
The server emits a redirect whose **host** is the canary, via: a `Location`
header (30x), a `<meta http-equiv=refresh>`, or a JS `location.*` assignment.
Backslashes are normalized (browsers treat `\` as `/`), so `/\canary` counts.

## Where open redirects hide
- Params: `redirect`, `redirect_uri`, `next`, `return`, `returnUrl`, `continue`,
  `goto`, `url`, `dest`, `callback`, `r`, `u`, `success`, `cancel_url`, `back`.
- Login / SSO / OAuth flows (highest value — token/code theft).
- Logout, email links, post-action "continue" pages.

## Bypasses to try when a naive payload is filtered
| Filter | Bypass |
|--------|--------|
| blocks `http://evil` | `//evil`, `/\evil`, `/%2f%2fevil` |
| requires leading `/` | `/\evil`, `/%09/evil`, `///evil` |
| allowlist contains target | `https://target.com@evil`, `https://evil/target.com`, `https://target.com.evil` |
| strips `//` | `/\/evil`, `\\evil` |
| appends a fixed suffix | `evil#`, `evil?`, `evil\@target` |
| decodes once | `%252f%252fevil` (double-encoded) |

All are in `open_redirect.py`'s payload set; add more with the `PAYLOADS` list.

## Chaining (prove in scope, by hand)
- **OAuth / SSO token or code theft → account takeover.** If the redirect sits
  in an auth flow (`redirect_uri`, `returnUrl` after login), try to make the
  `code`/token/`access_token` land on your canary. This is the high-severity path.
- **Credential phishing.** A redirect on the real domain lends a phishing page
  legitimacy; usually low/medium alone.
- **SSRF.** If the *server* follows the redirect (not the browser), it may be an
  SSRF primitive — test with your OOB listener.
- **CRLF + open redirect.** A `Location`-injecting CRLF is a redirect too; cross-
  reference crlf-hunter results.

## Severity guidance (suggest, let the program decide)
- Plain browser redirect, no auth context: **low** (some programs mark N/A).
- Redirect leaking an OAuth code/token, or → ATO: **high**.
- Redirect the server follows → SSRF: rate per the SSRF impact.

## Reporting
`report_openredirect.md` has a per-finding draft. A good report shows: the exact
request, the response `Location` (or meta/JS) pointing at your canary, and a
browser screenshot/recording of the redirect actually happening. State only the
impact you demonstrated; mark chains as candidate until proven.

## Public resources
- PayloadsAllTheThings — Open Redirect: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect
- OWASP — Unvalidated Redirects & Forwards cheat sheet: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- HackTricks (search "Open Redirect"): https://book.hacktricks.wiki
- Oralyzer — open-redirect scanner, good for cross-checking a hit: https://github.com/r0075h3ll/Oralyzer
- Learn from disclosed bugs — search "open redirect" on HackerOne Hacktivity: https://hackerone.com/hacktivity
