<div align="center">

```
 __   _   _  ___  _  _  ___  _   _ _  _ ___
| _ ) | | | |/ __|| || |/ _ \| | | | \| |   \
| _ \ | |_| | (_ || __ | (_) | |_| | .` | |) |
|___/  \___/ \___||_||_|\___/ \___/|_|\_|___/
```

**A bug bounty recon and multi-vulnerability scanning framework.**

Runs recon once, then hunts several bug classes over the same results, keeps the noise down, and leaves the final call to you.

</div>

---

## What it is

Bughound started as a CRLF scanner and grew into a small framework. You give it a scope file and a target, it enumerates and crawls once, then runs the scanners you pick against the shared results. Everything lands in one report, grouped by bug type, confirmed findings first.

The thing it tries hardest to do well is **not waste your time**. A scanner that prints a thousand "findings" is useless, because you still have to check each one by hand. Bughound filters aggressively: it double-confirms, it ignores reflections that encode their input, it knows that a `Location:` header echoing your URL is not CRLF, and it tells you plainly when it found nothing. The goal is a short list you can actually work through.

## Features

- **One command, many scanners.** Recon runs once. Pick the modules you want and they all test the same discovered hosts and parameters.
- **Six scanners:** CRLF / header injection, open redirect, reflected XSS context analysis, subdomain takeover, exposed-interface discovery, and JavaScript analysis (endpoints, secrets, source maps, DOM sinks).
- **Scope that actually holds.** An allow / deny scope file with wildcard and exclusion support. Out-of-scope hosts are dropped before any request is sent.
- **Low false positives by design.** Double confirmation, encoding-aware checks, and per-class heuristics that were tuned against real false positives from live programs.
- **Concurrent and polite.** Many hosts are tested in parallel, but each individual host is rate-limited, so full coverage stays fast without hammering any one server.
- **Resume without re-recon.** Recon is the expensive part. Save the parameter list once and re-scan it as often as you like.
- **Optional alerts.** Get a ping on Discord or Telegram the moment something worth looking at shows up, while the scan keeps running.
- **Optional LLM triage.** If you want it, a language model can sort real from false and draft a report. It is off by default and never required.

## The modules

| Module | Finds | Notes |
|--------|-------|-------|
| `crlf` | CRLF / HTTP header injection | double-confirmed, ignores `Location:` reflections |
| `open-redirect` | redirects to an attacker host | 70 bypass payloads, detects header / meta / JS redirects |
| `xss` | reflected XSS context | reports context and un-encoded breakout chars, not blind guesses |
| `takeover` | dangling-DNS subdomain takeover | ~25 service fingerprints, optional CNAME / NXDOMAIN checks |
| `hosts` | exposed panels and internal tools | ranks live hosts worth opening in a browser |
| `jsrecon` | endpoints, secrets, source maps, DOM sinks | the fix for "recon found no parameters" on SPAs |

## Quick start

```bash
# dependencies
pip3 install -r requirements.txt
bash install.sh                 # recon + scanning tools (Go based)

# scope: one host per line, * for wildcards, ! to exclude
printf '*.target.com\n!internal.target.com\n' > scope.target.txt

# run
python3 hunt.py -d "*.target.com" --scope scope.target.txt \
    --modules takeover,hosts,jsrecon,open-redirect,crlf,xss
```

Results land in `hunt_target.com/report.md`, plus a file per module.

## Picking how deep to go

```
--no-crawl      archives only, fast, good for huge targets
(default)       archives plus a crawl of the first 60 live hosts
--crawl-all     crawl every live host in batches, slow but thorough
```

Rate limiting is per host, so `--workers` sets how many different hosts are hit at once and `--delay` sets the gap between requests to the same host. On a big target, `--workers 15 --delay 1` gives full coverage in hours while keeping each server at one request per second.

## Resume a scan without redoing recon

```bash
# recon writes params to the output folder; re-fuzz it any time
python3 crlf_hunt.py -d "*.target.com" --scope scope.target.txt \
    --params-file hunt_target.com/params.txt --delay 0.3 --max-tests 200000
```

## Alerts while you are away

Set one of these and the scan pings you on anything worth a look, then keeps going:

```bash
export NOTIFY_DISCORD_WEBHOOK="https://discord.com/api/webhooks/..."
# or
export NOTIFY_TELEGRAM_TOKEN="..."; export NOTIFY_TELEGRAM_CHAT="..."
```

With nothing set it still writes `ALERTS.md` and rings the terminal bell.

## How it keeps the noise down

A few examples of false positives it was taught to ignore, because they came up on real programs:

- **CRLF:** a token echoed inside a `Location` header on a redirect is reflection, not injection. Only a token that becomes its own header line counts.
- **XSS:** a value reflected URL-encoded (`%22`) into an `og:url` meta tag on a 404 page is not exploitable. It checks the text between two markers, so a `content="` delimiter cannot pose as an un-encoded quote.
- **Takeover:** a CNAME to a known service only counts when the service's unclaimed-page fingerprint is actually present, or the CNAME target no longer resolves.

Every finding still needs you to reproduce it by hand before reporting. The tool narrows the field; it does not replace judgment.

## Layout

```
hunt.py              one command that runs the modules
crlf_hunt.py         shared recon and scope engine, plus the CRLF scanner
open_redirect.py     open redirect scanner
xss_reflected.py     reflected XSS context analysis
subdomain_takeover.py  takeover checker
triage_hosts.py      exposed-interface ranking
js_recon.py          JavaScript analysis
notify.py            Discord / Telegram alerts
report_agent.py      report builder
banner.py            startup banner
skills/              methodology notes per bug class
docs/                install, usage, chaining, reporting
```

## Install

See [`docs/INSTALL.md`](docs/INSTALL.md) for the full setup on WSL, Ubuntu, or Kali. Short version: Python 3, Go, and a handful of recon tools (`subfinder`, `httpx`, `katana`, `gau`, `waybackurls`), plus optional scanners (`crlfuzz`, `crlfsuite`, `nuclei`) that are used when present and skipped when not.

## Disclaimer

For authorized security testing only. Test your own assets, or a bug bounty program whose scope you have confirmed. You are responsible for staying inside that scope and the law. The tool and its reports are drafting aids, not proof of a vulnerability. Reproduce every finding by hand before you disclose it.

## License

MIT. See [`LICENSE`](LICENSE).
