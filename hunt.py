#!/usr/bin/env python3
"""
hunt.py: unified launcher for the crlf-hunter framework.

Recon runs ONCE, then every selected module tests the same discovered
parameters/hosts, and everything merges into a single report. Add a bug class
by writing a module function and registering it in MODULES below.

ONLY run against authorized targets. Scope (allow/deny, ! exclusions) is
enforced exactly as in the individual tools.

Usage:
  python3 hunt.py -d "*.target.com" --scope scope.txt \
      --modules crlf,open-redirect,hosts \
      --canary your-canary.com --oob-url YOURID.oast.live \
      --llm --llm-provider claude-code --no-crawl

Modules: crlf | open-redirect | hosts   (more coming: xss, lfi, ...)
"""
import argparse
import json
import os
import sys
import types
from pathlib import Path
from urllib.parse import urlparse

import crlf_hunt as core
import open_redirect as orr

try:
    import triage_hosts as th
except ImportError:
    th = None

try:
    import subdomain_takeover as sto
except ImportError:
    sto = None

try:
    import xss_reflected as xss
except ImportError:
    xss = None

try:
    import js_recon as jsr
except ImportError:
    jsr = None

try:
    import notify
except ImportError:
    notify = None

try:
    import banner
except ImportError:
    banner = None


def log(m):
    print(m, flush=True)


# ---------------------------------------------------------------- modules
def mod_crlf(args, cands):
    """CRLF / header injection -> normalized findings with triage."""
    log("\n=== module: crlf ===")
    payloads = core.load_lines(Path("crlf_payloads.txt")) if Path("crlf_payloads.txt").exists() \
        else (core.load_lines(Path("..") / "crlf_payloads.txt")
              if (Path("..") / "crlf_payloads.txt").exists() else core.BUILTIN_PAYLOADS)
    findings = core.builtin_fuzz(args, cands, payloads)
    enabled = [e.strip() for e in args.engines.split(",")]
    if "crlfuzz" in enabled:
        findings += core.engine_crlfuzz(cands)
    if "crlfsuite" in enabled:
        findings += core.engine_crlfsuite(cands)
    if "nuclei" in enabled:
        findings += core.engine_nuclei(cands)
    out = []
    for f in findings:
        t = core.llm_triage(f, args) if args.llm else {}
        out.append({"type": "crlf", "url": f.get("url"), "param": f.get("param"),
                    "payload": f.get("payload"), "evidence": f.get("evidence"),
                    "confirmed": f.get("confirmed"), "engine": f.get("engine"),
                    "severity": (t or {}).get("severity", "-"),
                    "real": (t or {}).get("real"), "triage": t})
    return out


def mod_openredirect(args, cands):
    """Open redirect -> normalized findings with triage."""
    log("\n=== module: open-redirect ===")
    pool = orr.load_payloads(getattr(args, "or_payloads", "payloads/open_redirect.txt"))
    findings = orr.hunt(args, cands, args.canary, pool)
    out = []
    for f in findings:
        t = orr.triage(f, args, args.canary) if args.llm else {}
        out.append({"type": "open-redirect", "url": f.get("url"), "param": f.get("param"),
                    "payload": f.get("payload"), "evidence": f.get("evidence"),
                    "where": f.get("where"), "confirmed": f.get("confirmed"),
                    "severity": (t or {}).get("severity", "-"),
                    "real": (t or {}).get("real"), "triage": t})
    return out


def mod_hosts(args, cands):
    """Exposed-interface discovery over the live hosts recon already found."""
    log("\n=== module: hosts ===")
    if th is None:
        log("[-] triage_hosts.py not found; skipping hosts module")
        return []
    if not Path("live.txt").exists():
        log("[-] no live.txt from recon; skipping hosts module")
        return []
    lines = core.run(["httpx", "-l", "live.txt", "-silent", "-sc", "-title",
                      "-cl", "-td"]) or [l.strip() for l in Path("live.txt").read_text().splitlines() if l.strip()]
    results = []
    for i in range(0, len(lines), 35):
        batch = lines[i:i + 35]
        if args.llm:
            res = th.triage_batch(batch, args.llm_provider, args.model,
                                  args.llm_base_url, args.target)
        else:
            res = []
        if len(res) != len(batch):
            res = [{"host": l.split()[0] if l.split() else l, "verdict": "review",
                    "type": "?", "reason": "not triaged - review manually"} for l in batch]
        results.extend(res)
    review = [r for r in results if str(r.get("verdict", "")).lower() == "review"]
    out = ["# Exposed-interface triage", "",
           "> Open the Review hosts in a browser; a login/block page alone is not a finding.", "",
           f"## Review ({len(review)})", ""]
    out += [f"- [ ] **{r.get('host')}** — _{r.get('type','?')}_ — {r.get('reason','')}" for r in review]
    Path("hosts_triage.md").write_text("\n".join(out))
    log(f"[*] hosts: {len(review)} to review -> hosts_triage.md")
    # surface as findings so the combined report references them
    return [{"type": "exposed-host", "url": r.get("host"), "param": "-", "payload": "-",
             "evidence": r.get("reason"), "confirmed": None, "severity": "info",
             "real": None, "triage": r} for r in review]


def mod_takeover(args, cands):
    """Subdomain takeover over the enumerated subdomains recon saved."""
    log("\n=== module: takeover ===")
    if sto is None:
        log("[-] subdomain_takeover.py not found; skipping")
        return []
    src = "subs.txt" if Path("subs.txt").exists() else ("live.txt" if Path("live.txt").exists() else None)
    if not src:
        log("[-] no subs.txt/live.txt from recon; skipping takeover")
        return []
    scope = core.load_lines(Path("..") / args.scope) if (Path("..") / args.scope).exists() \
        else core.load_lines(args.scope)
    hosts = [l.strip().replace("https://", "").replace("http://", "").split("/")[0]
             for l in Path(src).read_text().splitlines() if l.strip()]
    findings = sto.run_check(sorted(set(hosts)), scope)
    return [{"type": "subdomain-takeover", "url": f["host"], "param": "-",
             "payload": "-", "evidence": f"{f['service']} | {f['signal']} | CNAME {f['cname']}",
             "confirmed": f["confidence"] == "high", "severity":
             {"high": "high", "medium": "medium", "manual": "info"}.get(f["confidence"], "info"),
             "real": None, "triage": f} for f in findings]


def mod_xss(args, cands):
    """Reflected-XSS reflection/context detection on the shared params."""
    log("\n=== module: xss ===")
    if xss is None:
        log("[-] xss_reflected.py not found; skipping")
        return []
    findings = xss.hunt(args, cands)
    return [{"type": "xss-reflected", "url": f["url"], "param": f["param"],
             "payload": f.get("suggested_payload"),
             "evidence": f"context={f['context']} unencoded={''.join(f['unencoded'])}",
             "confirmed": False,  # reflection only; execution is a manual step
             "severity": "high" if f.get("likely_exploitable") else "low",
             "real": None, "triage": f} for f in findings]


def mod_jsrecon(args, cands):
    """JS analysis: endpoints, secrets, source maps, DOM-XSS sink leads."""
    log("\n=== module: jsrecon ===")
    if jsr is None:
        log("[-] js_recon.py not found; skipping")
        return []
    args.js_list = getattr(args, "js_list", None)
    scope = core.load_lines(Path("..") / args.scope) if (Path("..") / args.scope).exists() \
        else core.load_lines(args.scope)
    js = jsr.collect_js(args, scope)
    if not js:
        log("[-] no in-scope JS found")
        return []
    res = jsr.run_jsrecon(js, scope)
    jsr.write_outputs(res, args.target)
    out = []
    for s in res["secrets"]:
        out.append({"type": "secret", "url": s["file"], "param": "-",
                    "payload": "-", "evidence": f"{s['type']}: {s['match']}",
                    "confirmed": False, "severity": "high" if s["confidence"] == "high" else "medium",
                    "real": None, "triage": s})
    for sm in res["sourcemaps"]:
        out.append({"type": "source-map-exposed", "url": sm, "param": "-", "payload": "-",
                    "evidence": "exposed .map (original source)", "confirmed": True,
                    "severity": "low", "real": None, "triage": {}})
    return out


MODULES = {"crlf": mod_crlf, "open-redirect": mod_openredirect,
           "hosts": mod_hosts, "takeover": mod_takeover,
           "xss": mod_xss, "jsrecon": mod_jsrecon}

SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "-": 5, None: 5}


# ---------------------------------------------------------------- report
def write_combined(all_findings, target):
    by_type = {}
    for f in all_findings:
        by_type.setdefault(f["type"], []).append(f)
    doc = [f"# Recon + Vuln Report — {target}", "",
           "> DRAFT. Reproduce every finding by hand before reporting. "
           "LLM verdicts and engine flags are leads, not proof.", "",
           "## Summary", ""]
    for t, fs in by_type.items():
        conf = sum(1 for f in fs if f.get("confirmed"))
        doc.append(f"- **{t}**: {len(fs)} findings"
                   + (f" ({conf} confirmed)" if any(f.get('confirmed') is not None for f in fs) else ""))
    doc.append("")
    for t, fs in by_type.items():
        fs.sort(key=lambda f: (not f.get("confirmed"), SEV.get(f.get("severity"), 5)))
        doc += [f"\n## {t} ({len(fs)})", ""]
        for i, f in enumerate(fs, 1):
            host = urlparse(f["url"]).hostname or f["url"]
            tri = f.get("triage") or {}
            doc += [f"### {i}. {f.get('param')} @ {host}",
                    f"- confirmed: {f.get('confirmed')} · severity(LLM): {f.get('severity','-')}"
                    + (f" · real: {f.get('real')}" if f.get('real') is not None else ""),
                    f"- payload: `{f.get('payload')}`" if f.get("payload") not in ("-", None) else "",
                    "PoC:", "```bash", f"curl -sS -i '{f['url']}'", "```"]
            if f.get("evidence"):
                ev = f["evidence"]
                doc += ["Evidence:", "```", "\n".join(ev) if isinstance(ev, list) else str(ev), "```"]
            if tri.get("report_md"):
                doc += ["", "Report draft (edit before use):", "", tri["report_md"]]
            doc += ["", "---", ""]
    Path("report.md").write_text("\n".join([d for d in doc if d is not None]))


def recon_args(args):
    return types.SimpleNamespace(
        url=args.url, domain=args.domain, oob_url=args.oob_url,
        no_crawl=args.no_crawl, crawl_all=args.crawl_all,
        crawl_cap=args.crawl_cap, wayback_cap=args.wayback_cap)


def main():
    ap = argparse.ArgumentParser(description="Unified recon + multi-vuln hunter")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-d", "--domain")
    g.add_argument("-u", "--url")
    ap.add_argument("--scope", required=True)
    ap.add_argument("--modules", default="crlf,open-redirect",
                    help="comma list: " + " | ".join(MODULES))
    ap.add_argument("--canary", default="example.com")
    ap.add_argument("--oob-url", dest="oob_url")
    ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--max-tests", type=int, default=5000)
    ap.add_argument("--workers", type=int, default=15, help="hosts fuzzed in parallel")
    ap.add_argument("--engines", default="builtin,crlfuzz,crlfsuite,nuclei")
    ap.add_argument("--no-crawl", action="store_true")
    ap.add_argument("--crawl-all", dest="crawl_all", action="store_true")
    ap.add_argument("--crawl-cap", dest="crawl_cap", type=int, default=60)
    ap.add_argument("--wayback-cap", dest="wayback_cap", type=int, default=400)
    ap.add_argument("--llm", action="store_true")
    ap.add_argument("--llm-provider", default="claude-code",
                    choices=["claude-code", "anthropic", "openai", "ollama"])
    ap.add_argument("--llm-base-url")
    ap.add_argument("--model", default="llama3.1")
    args = ap.parse_args()

    scope = core.load_lines(args.scope)
    args.target = (args.domain or urlparse(args.url if args.url.startswith("http")
                   else "https://" + args.url).hostname).lstrip("*.")
    if not core.in_scope(args.target, scope):
        sys.exit(f"[!] {args.target} is not in scope.txt. Stopping.")

    chosen = [m.strip() for m in args.modules.split(",") if m.strip() in MODULES]
    if not chosen:
        sys.exit(f"[!] no valid modules. Choose from: {', '.join(MODULES)}")

    if banner is not None:
        banner.show(modules=chosen, target=args.target)

    workdir = Path(f"hunt_{args.target}")
    workdir.mkdir(exist_ok=True)
    os.chdir(workdir)
    log(f"[*] output: {workdir.resolve()}")
    log(f"[*] modules: {', '.join(chosen)}")

    # --- recon ONCE ---
    cands = core.recon(recon_args(args), scope)
    log(f"[*] shared recon: {len(cands)} param URLs, live hosts in live.txt")

    all_findings = []
    for m in chosen:
        try:
            mod_findings = MODULES[m](args, cands)
            all_findings += mod_findings
            # alert on noteworthy results, then keep going
            if notify is not None:
                try:
                    sent = notify.notify_findings(mod_findings)
                    if sent:
                        log(f"[*] {sent} noteworthy finding(s) alerted")
                except Exception as e:
                    log(f"[!] notify failed (non-fatal): {e}")
        except Exception as e:  # one module failing never kills the rest
            log(f"[!] module {m} failed: {e}")

    Path("findings.json").write_text(json.dumps(all_findings, indent=2, default=str))
    write_combined(all_findings, args.target)
    log(f"\nDone. {len(all_findings)} findings across {len(chosen)} modules.")
    log(f"See {workdir.resolve()}/report.md")


if __name__ == "__main__":
    main()
