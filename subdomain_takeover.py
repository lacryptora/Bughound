#!/usr/bin/env python3
"""
subdomain_takeover.py: dangling-DNS / subdomain-takeover checker.

For each in-scope subdomain it fetches the host and matches the response against
a fingerprint database of third-party services that show a recognizable
"unclaimed" page (GitHub Pages, S3, Heroku, Shopify, Fastly, ...). A CNAME to
such a service + its unclaimed fingerprint = a likely takeover.

HTTP-body fingerprinting is the core (no DNS library needed). If dnspython is
installed, the CNAME is resolved too and raises confidence.

ONLY run against authorized targets. Detection only — it never registers or
claims anything. A positive fingerprint still MUST be confirmed and claimed
responsibly (or just reported) by you.

Standalone:
  subfinder -d target.com -silent > subs.txt
  python3 subdomain_takeover.py --in subs.txt --scope scope.txt
Or it runs inside hunt.py as the `takeover` module (reads recon's subs.txt).
"""
import argparse
import concurrent.futures as cf
import json
import sys
from pathlib import Path

import requests

try:
    import dns.resolver  # optional, improves accuracy
except ImportError:
    dns = None

import crlf_hunt as core

UA = "Mozilla/5.0 (takeover-check; authorized testing)"

# service, CNAME substrings, body fingerprint (unclaimed page), nxdomain-based?
FINGERPRINTS = [
    ("GitHub Pages", ["github.io"], "There isn't a GitHub Pages site here", False),
    ("AWS/S3", ["s3", "amazonaws.com"], "NoSuchBucket", False),
    ("Heroku", ["herokudns.com", "herokuapp.com", "herokussl.com"], "No such app", False),
    ("Heroku", ["herokudns.com", "herokuapp.com"], "no-such-app.html", False),
    ("Shopify", ["myshopify.com"], "Sorry, this shop is currently unavailable", False),
    ("Fastly", ["fastly.net"], "Fastly error: unknown domain", False),
    ("Pantheon", ["pantheonsite.io"], "The gods are wise, but do not know of the site", False),
    ("Tumblr", ["domains.tumblr.com"], "Whatever you were looking for doesn't currently exist", False),
    ("WordPress", ["wordpress.com"], "Do you want to register", False),
    ("Ghost", ["ghost.io"], "The thing you were looking for is no longer here", False),
    ("Surge.sh", ["surge.sh"], "project not found", False),
    ("Bitbucket", ["bitbucket.io"], "Repository not found", False),
    ("Unbounce", ["unbouncepages.com"], "The requested URL was not found on this server", False),
    ("Webflow", ["proxy-ssl.webflow.com", "webflow.io"], "The page you are looking for doesn't exist or has been moved", False),
    ("Netlify", ["netlify.app", "netlify.com"], "Not Found - Request ID", False),
    ("Zendesk", ["zendesk.com"], "Help Center Closed", False),
    ("Readthedocs", ["readthedocs.io"], "unknown to Read the Docs", False),
    ("Cargo", ["cargocollective.com"], "404 Not Found", False),
    ("Helpjuice", ["helpjuice.com"], "We could not find what you're looking for", False),
    ("Help Scout", ["helpscoutdocs.com"], "No settings were found for this company", False),
    ("Teamwork", ["teamwork.com"], "Oops - We didn't find your site", False),
    ("Intercom", ["custom.intercom.help"], "This page is reserved for artistic dogs", False),
    ("Wix", ["wixdns.net"], "Error ConnectYourDomain occurred", False),
    # NXDOMAIN-based (CNAME to a provider whose target no longer resolves)
    ("Azure", ["azurewebsites.net", "cloudapp.net", "trafficmanager.net",
               "azureedge.net", "azure-api.net", "cloudapp.azure.com"], "", True),
    ("AWS Elastic Beanstalk", ["elasticbeanstalk.com"], "", True),
]


def cname_chain(host):
    if dns is None:
        return []
    chain = []
    try:
        ans = dns.resolver.resolve(host, "CNAME")
        for r in ans:
            chain.append(str(r.target).rstrip(".").lower())
    except Exception:
        pass
    return chain


def resolves(host):
    if dns is None:
        return True  # unknown; don't claim NXDOMAIN without a resolver
    try:
        dns.resolver.resolve(host, "A")
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except Exception:
        return True


def check(host):
    host = host.strip()
    if not host:
        return None
    body, status = "", None
    for scheme in ("https://", "http://"):
        try:
            r = requests.get(scheme + host, headers={"User-Agent": UA},
                             timeout=10, allow_redirects=True)
            body, status = r.text or "", r.status_code
            break
        except requests.RequestException:
            continue
    cn = cname_chain(host)
    cn_str = " ".join(cn)
    for service, cnames, fp, nx in FINGERPRINTS:
        cname_hit = any(c in cn_str for c in cnames)
        if nx:
            # NXDOMAIN takeover: CNAME to provider but the target doesn't resolve
            if cname_hit and cn and not resolves(cn[-1]):
                return {"host": host, "service": service, "signal": "CNAME->NXDOMAIN",
                        "cname": cn_str, "status": status, "confidence": "high"}
        else:
            if fp and fp.lower() in body.lower():
                conf = "high" if cname_hit or dns is None else "medium"
                return {"host": host, "service": service, "signal": f"body: {fp[:40]}",
                        "cname": cn_str, "status": status, "confidence": conf}
    # CNAME to a known service with no page yet = worth a manual look
    for service, cnames, fp, nx in FINGERPRINTS:
        if any(c in cn_str for c in cnames) and status in (404, None):
            return {"host": host, "service": service, "signal": "CNAME match, no live page",
                    "cname": cn_str, "status": status, "confidence": "manual"}
    return None


def run_check(hosts, scope, workers=20):
    hosts = [h for h in hosts if core.in_scope(h, scope)]
    findings = []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for res in ex.map(check, hosts):
            if res:
                findings.append(res)
                print(f"[TAKEOVER? {res['confidence']}] {res['host']} -> "
                      f"{res['service']} ({res['signal']})", flush=True)
    return findings


def write_report(findings, target):
    out = [f"# Subdomain Takeover Candidates - {target}", "",
           "> DRAFT. Confirm by claiming the resource on the named service (or just "
           "report). 'manual' confidence = CNAME points at a service but no "
           "fingerprint yet; verify by hand. Authorized testing only.", ""]
    for i, f in enumerate(sorted(findings, key=lambda x: x["confidence"]), 1):
        out += [f"## {i}. {f['host']}  ({f['confidence']})",
                f"- service: **{f['service']}**",
                f"- signal: {f['signal']}",
                f"- CNAME: `{f['cname'] or '(none resolved)'}`",
                f"- HTTP status: {f['status']}", "",
                "Verify:",
                f"```bash",
                f"dig CNAME {f['host']}",
                f"curl -sS -i https://{f['host']}",
                "```",
                "If the service shows an unclaimed page and the CNAME target is "
                "registerable, this is a takeover. Report with the CNAME, the "
                "fingerprint, and (if you claim it responsibly) a benign proof page.", "",
                "---", ""]
    Path("report_takeover.md").write_text("\n".join(out))


def main():
    ap = argparse.ArgumentParser(description="Subdomain-takeover checker")
    ap.add_argument("--in", dest="inp", help="file of subdomains (default subs.txt)")
    ap.add_argument("-d", "--domain", help="enumerate this domain first (needs subfinder)")
    ap.add_argument("--scope", required=True)
    args = ap.parse_args()

    scope = core.load_lines(args.scope)
    if args.domain:
        hosts = core.run(["subfinder", "-d", args.domain.lstrip("*."), "-all", "-silent"]) or []
        target = args.domain.lstrip("*.")
    else:
        src = args.inp or "subs.txt"
        if not Path(src).exists():
            sys.exit(f"[!] {src} not found. Pass --in or -d.")
        hosts = [l.strip() for l in Path(src).read_text().splitlines() if l.strip()]
        target = "target"
    if dns is None:
        print("[i] dnspython not installed - body-fingerprint mode only "
              "(pip install dnspython for CNAME/NXDOMAIN checks)")
    print(f"[*] checking {len(hosts)} subdomains for takeover")
    findings = run_check(hosts, scope)
    Path("takeover_findings.json").write_text(json.dumps(findings, indent=2))
    write_report(findings, target)
    print(f"\n[*] {len(findings)} candidates -> report_takeover.md")


if __name__ == "__main__":
    main()
