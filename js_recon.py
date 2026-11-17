#!/usr/bin/env python3
"""
js_recon.py: JavaScript analysis — endpoints, secrets, source maps, DOM sinks.

Collects in-scope JS, then mines each file for:
  - endpoints / API paths / full URLs (jsluice if installed, else regex)
  - secrets & API keys (high/medium-confidence pattern DB)
  - exposed source maps (.map) — near-original source
  - DOM-XSS sinks (innerHTML, eval, document.write, location, postMessage...) as
    LEADS for the xss / dom-xss methodology, not confirmed bugs

ONLY run against authorized targets. Scope enforced via --scope. Downloading and
reading JS is passive. Secrets found must be validated by you (see the
api-key-leaks methodology) and reported — never used.

Standalone:
  python3 js_recon.py -d target.com --scope scope.txt
  python3 js_recon.py --js-list jsfiles.txt --scope scope.txt
Also runs as the `jsrecon` module in hunt.py.
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

import requests

import crlf_hunt as core

UA = "Mozilla/5.0 (js-recon; authorized testing)"

# High-confidence secret patterns (prefix-anchored -> few false positives).
SECRET_PATTERNS = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}", "high"),
    ("AWS MWS Key", r"amzn\.mws\.[0-9a-f-]{36}", "high"),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", "high"),
    ("Google OAuth Token", r"ya29\.[0-9A-Za-z\-_]+", "high"),
    ("GitHub Token", r"gh[pousr]_[0-9A-Za-z]{36,}", "high"),
    ("Slack Token", r"xox[baprs]-[0-9A-Za-z-]{10,48}", "high"),
    ("Slack Webhook", r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+", "high"),
    ("Stripe Live Key", r"sk_live_[0-9a-zA-Z]{24,}", "high"),
    ("Stripe Restricted", r"rk_live_[0-9a-zA-Z]{24,}", "high"),
    ("SendGrid Key", r"SG\.[\w-]{22}\.[\w-]{43}", "high"),
    ("Twilio SID", r"AC[0-9a-fA-F]{32}", "high"),
    ("Mailgun Key", r"key-[0-9a-zA-Z]{32}", "high"),
    ("Facebook Access Token", r"EAACEdEose0cBA[0-9A-Za-z]+", "high"),
    ("Firebase Cloud Msg", r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}", "high"),
    ("Private Key Block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "high"),
    ("JWT", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "medium"),
    ("Google Service Acct", r'"type":\s*"service_account"', "high"),
    ("Generic api_key/secret", r"(?i)(?:api[_-]?key|apikey|client[_-]?secret|access[_-]?token|auth[_-]?token)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\-_.]{16,}['\"]", "medium"),
]

# DOM-XSS sinks: user-influenced data flowing into these can execute. Leads only.
DOM_SINKS = [
    "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "document.writeln",
    "eval(", "setTimeout(", "setInterval(", "Function(", "location.href", "location.replace",
    "location.assign", "window.location", "document.location", "jQuery.html", ".html(",
    "dangerouslySetInnerHTML", "$(", "srcdoc", "setAttribute(", "execScript",
]
# DOM-XSS sources: attacker-controllable inputs. A sink fed by a source = DOM XSS candidate.
DOM_SOURCES = [
    "location.hash", "location.search", "location.href", "document.URL", "document.referrer",
    "document.cookie", "window.name", "postMessage", "localStorage", "sessionStorage",
    "URLSearchParams",
]


def log(m):
    print(m, flush=True)


def collect_js(args, scope):
    """Gather in-scope .js URLs via gau/katana (or a provided list)."""
    if args.js_list:
        urls = core.load_lines(args.js_list)
    else:
        seed = (args.domain or urlparse(args.url).hostname).lstrip("*.")
        urls = set()
        if shutil.which("gau"):
            urls.update(core.run(["gau", "--subs", seed], timeout=300) or [])
        if shutil.which("katana"):
            start = args.url or ("https://" + seed)
            urls.update(core.run(["katana", "-u", start, "-jc", "-d", "2", "-silent"],
                                 timeout=300) or [])
        urls = [u for u in urls if ".js" in u.lower()]
    js = sorted({u for u in urls
                 if re.search(r"\.js(\?|$)", u, re.I)
                 and core.in_scope(urlparse(u).hostname, scope)})
    # confirm live
    if shutil.which("httpx") and js:
        live = core.run(["httpx", "-silent", "-mc", "200"], stdin="\n".join(js)) or js
        js = [u for u in live if core.in_scope(urlparse(u).hostname, scope)]
    log(f"[*] {len(js)} in-scope JS files")
    return js


def analyze(text, url):
    """Mine one JS file's content. Returns endpoints, secrets, sinks."""
    endpoints = set()
    # full URLs and absolute paths
    for m in re.finditer(r'["\'`](https?://[^"\'`\s]+|/[a-zA-Z0-9_?&=./-]{2,120})["\'`]', text):
        v = m.group(1)
        if not v.lower().endswith((".png", ".jpg", ".svg", ".css", ".woff", ".gif", ".ico")):
            endpoints.add(v)
    # jsluice for better extraction if present
    if shutil.which("jsluice"):
        try:
            p = subprocess.run(["jsluice", "urls"], input=text, capture_output=True,
                               text=True, timeout=30)
            for line in p.stdout.splitlines():
                try:
                    endpoints.add(json.loads(line).get("url", ""))
                except ValueError:
                    pass
        except subprocess.TimeoutExpired:
            pass

    secrets = []
    for name, pat, conf in SECRET_PATTERNS:
        for m in re.finditer(pat, text):
            val = m.group(0)
            secrets.append({"type": name, "confidence": conf,
                            "match": val[:80], "file": url})

    sinks = []
    for sink in DOM_SINKS:
        if sink in text:
            # note nearby sources to rank DOM-XSS likelihood
            near = [s for s in DOM_SOURCES if s in text]
            sinks.append({"sink": sink, "sources_in_file": near})
    return sorted(e for e in endpoints if e), secrets, sinks


def check_sourcemap(session, url):
    try:
        r = session.get(url + ".map", timeout=8)
        if r.status_code == 200 and ('"mappings"' in r.text[:2000] or '"sources"' in r.text[:2000]):
            return True
    except requests.RequestException:
        pass
    return False


def run_jsrecon(js_urls, scope):
    s = requests.Session()
    s.headers["User-Agent"] = UA
    all_endpoints, all_secrets, sink_files, sourcemaps = set(), [], [], []
    for url in js_urls:
        if not core.in_scope(urlparse(url).hostname, scope):
            continue
        try:
            r = s.get(url, timeout=15)
            text = r.text or ""
        except requests.RequestException:
            continue
        eps, secs, sinks = analyze(text, url)
        all_endpoints.update(eps)
        all_secrets.extend(secs)
        if sinks:
            sink_files.append({"file": url, "sinks": sinks})
        if check_sourcemap(s, url):
            sourcemaps.append(url + ".map")
            log(f"[SOURCEMAP] {url}.map  (exposed original source!)")
        for sec in secs:
            log(f"[SECRET {sec['confidence']}] {sec['type']} in {url}")
    return {
        "endpoints": sorted(all_endpoints),
        "secrets": all_secrets,
        "sourcemaps": sourcemaps,
        "dom_sink_files": sink_files,
    }


def write_outputs(res, target):
    Path("js_endpoints.txt").write_text("\n".join(res["endpoints"]) + "\n")
    Path("js_findings.json").write_text(json.dumps(res, indent=2))
    out = [f"# JS Analysis — {target}", "",
           f"- endpoints extracted: {len(res['endpoints'])} (js_endpoints.txt)",
           f"- secrets: {len(res['secrets'])}",
           f"- exposed source maps: {len(res['sourcemaps'])}",
           f"- files with DOM-XSS sinks: {len(res['dom_sink_files'])}", ""]
    if res["secrets"]:
        out += ["## Secrets (validate before reporting — never use them)", ""]
        for s in sorted(res["secrets"], key=lambda x: x["confidence"]):
            out.append(f"- **{s['type']}** ({s['confidence']}) — `{s['match']}` — {s['file']}")
        out.append("")
    if res["sourcemaps"]:
        out += ["## Exposed source maps (download for near-original source)", ""]
        out += [f"- {u}" for u in res["sourcemaps"]] + [""]
    if res["dom_sink_files"]:
        out += ["## DOM-XSS leads (sink + source in same file -> investigate by hand)", ""]
        for f in res["dom_sink_files"]:
            hot = [s for s in f["sinks"] if s["sources_in_file"]]
            tag = "  ⚠ source+sink" if hot else ""
            out.append(f"- {f['file']}{tag}")
            for s in f["sinks"]:
                src = f" (sources: {', '.join(s['sources_in_file'])})" if s["sources_in_file"] else ""
                out.append(f"    - `{s['sink']}`{src}")
        out.append("")
    Path("report_jsrecon.md").write_text("\n".join(out))
    log(f"[*] -> report_jsrecon.md, js_endpoints.txt, js_findings.json")


def main():
    ap = argparse.ArgumentParser(description="JS analysis: endpoints, secrets, source maps, DOM sinks")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-d", "--domain")
    g.add_argument("-u", "--url")
    g.add_argument("--js-list", dest="js_list", help="file of JS URLs to analyze directly")
    ap.add_argument("--scope", required=True)
    args = ap.parse_args()
    scope = core.load_lines(args.scope)
    target = (args.domain or (urlparse(args.url).hostname if args.url else "target")).lstrip("*.")
    js = collect_js(args, scope)
    if not js:
        sys.exit("[!] no in-scope JS files found")
    res = run_jsrecon(js, scope)
    write_outputs(res, target)


if __name__ == "__main__":
    main()
