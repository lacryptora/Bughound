---
name: subdomain-takeover
description: >-
  Check an AUTHORIZED target's subdomains for dangling-DNS / subdomain takeover.
  Trigger when the user asks to find subdomain takeover / dangling CNAME, or to
  run subdomain_takeover.py. One of the most beginner-friendly first bounties.
---

# subdomain-takeover

Find subdomains whose DNS points at a third-party service (GitHub Pages, S3,
Heroku, Shopify, Fastly, Azure, ...) that is unclaimed — an attacker can register
it and serve content from the target's subdomain. Uses `subdomain_takeover.py`
(shared crlf-hunter scope); runs standalone or as the `takeover` module in
`hunt.py`.

## Hard rules
1. **Authorization + scope.** Hosts are filtered against `scope.txt`.
2. **Detect only.** The tool never claims or registers a resource. Confirming a
   takeover by claiming it must be done responsibly (benign proof) or just
   reported — follow the program's policy.

## Run
```bash
# standalone
subfinder -d target.com -silent > subs.txt
python3 subdomain_takeover.py --in subs.txt --scope scope.txt
# or enumerate + check in one go
python3 subdomain_takeover.py -d target.com --scope scope.txt
# inside the unified runner (uses recon's subs.txt)
python3 hunt.py -d "*.target.com" --scope scope.txt --modules takeover
```
Optional but recommended: `pip install dnspython` — enables CNAME and
NXDOMAIN checks (Azure/Elastic Beanstalk style), raising accuracy.

## What counts
- **high** — CNAME to a provider + the provider's unclaimed fingerprint (or a
  CNAME whose target no longer resolves: NXDOMAIN takeover).
- **medium** — the unclaimed body fingerprint without a confirmed CNAME.
- **manual** — CNAME points at a known service but no fingerprint yet; verify by
  hand (the service may have changed its page).

## Confirm before reporting
```bash
dig CNAME sub.target.com         # see where it points
curl -sS -i https://sub.target.com   # see the unclaimed page
```
A real takeover: the CNAME target is registerable on that service AND the service
shows its "unclaimed" page. Then either claim it responsibly with a benign proof
page (e.g. a text file with your HackerOne handle) or report with the evidence.

## Severity
Usually **high** — an attacker serving content from a trusted subdomain enables
phishing, cookie theft (same registrable domain), and OAuth/redirect abuse.
Some programs rate it medium if the subdomain is unused/low-value.

## Reporting
`report_takeover.md` has a per-candidate draft. Include: the subdomain, the
`dig` CNAME output, the service's unclaimed-page screenshot, and your benign
proof if you claimed it. Never serve real malicious content.
