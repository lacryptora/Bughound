#!/usr/bin/env python3
"""
report_agent.py: turn crlf_hunt.py output into a complete, detailed report.

Reads a scan folder (findings.json, optional triage.json) and writes:
  REPORT_FULL.md        - one professional report: exec summary, methodology,
                          every finding in full (evidence, PoC, reproduction,
                          chaining, suggested CVSS, remediation), references.
  reports/finding_NN.md - a standalone HackerOne-style writeup per finding.
  findings.csv          - a tracking table.

The LLM writes the narrative; the evidence, payloads and PoCs are filled in
deterministically so the report is accurate even if the LLM is unavailable.
Nothing here is proof: every PoC must be reproduced by hand before reporting,
and no impact beyond the demonstrated evidence is claimed.

Run standalone:
  python3 report_agent.py --dir crlf_target.com --target target.com \
      --tester "you" --llm-provider claude-code

Or it is called automatically by crlf_hunt.py when --llm is set.
"""
import argparse
import csv
import datetime as dt
import json
import os
import re
import subprocess
from pathlib import Path

import requests

REFERENCES = [
    "OWASP: CRLF Injection - https://owasp.org/www-community/vulnerabilities/CRLF_Injection",
    "CWE-93: Improper Neutralization of CRLF Sequences - https://cwe.mitre.org/data/definitions/93.html",
    "CWE-113: Improper Neutralization of CRLF in HTTP Headers - https://cwe.mitre.org/data/definitions/113.html",
    "PortSwigger: HTTP request smuggling / response splitting - https://portswigger.net/web-security/request-smuggling",
    "GitLab git:// -> Redis SSRF->RCE (HackerOne #441090)",
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "-": 5}


# ---------------------------------------------------------------- LLM
def llm_call(prompt, provider, model, base_url):
    """One shared LLM call across the four providers. Returns text or ''."""
    try:
        if provider == "claude-code":
            try:
                p = subprocess.run(["claude", "-p", prompt],
                                   capture_output=True, text=True, timeout=180)
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
                json={"model": model, "max_tokens": 1500,
                      "messages": [{"role": "user", "content": prompt}]},
                timeout=120)
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


def llm_json(prompt, provider, model, base_url):
    text = llm_call(prompt, provider, model, base_url)
    m = re.search(r"\{.*\}", text, re.S)
    if m:
        try:
            return json.loads(m.group(0))
        except ValueError:
            pass
    return {}


# ------------------------------------------------- chaining (local copy)
FETCHER_PARAMS = {
    "url", "uri", "u", "dest", "destination", "redirect", "redirect_url",
    "redirect_uri", "next", "return", "returnurl", "return_url", "continue",
    "callback", "webhook", "proxy", "fetch", "feed", "image", "img", "file",
    "path", "git", "repo", "host", "port", "to", "out", "view", "domain",
    "site", "data", "reference", "ref", "target", "link", "load", "page",
}


def looks_like_fetcher(name):
    n = (name or "").lower()
    return n in FETCHER_PARAMS or any(
        k in n for k in ("url", "uri", "redirect", "host", "callback", "webhook", "fetch", "proxy"))


def chain_names(f):
    base = ["response splitting -> XSS", "response splitting -> web cache poisoning"]
    if "set-cookie" in " ".join(f.get("evidence", [])).lower() or looks_like_fetcher(f.get("param")):
        base.append("Set-Cookie -> session fixation")
        base.append("Location -> open redirect -> OAuth/ATO")
    if looks_like_fetcher(f.get("param")):
        base.append("SSRF -> protocol/queue injection -> RCE")
    return base


# ---------------------------------------------------------------- build
def per_finding_report(f, t, idx, provider, model, base_url):
    chains = chain_names(f)
    evidence = "\n".join(f.get("evidence", [])) or "(none captured)"
    prompt = f"""Write a complete, professional bug-bounty finding writeup in Markdown for an AUTHORIZED test. Use ONLY the facts below; do not invent impact, headers, or behaviour not shown. Where impact depends on a chain that is not yet proven, say "candidate / requires manual confirmation".

FACTS
Engine: {f.get('engine')}
URL: {f.get('url')}
Parameter: {f.get('param')} (server-side-fetcher-like: {looks_like_fetcher(f.get('param'))})
Payload: {f.get('payload')}
Response status: {f.get('status')}
Injected header evidence:
{evidence}
Double-confirmed by re-test: {f.get('confirmed')}
Candidate chains: {', '.join(chains)}
Prior triage (may be empty): {json.dumps(t)}

Produce these sections exactly:
## Title
## Severity (give a suggested CVSS 3.1 vector and base score, labelled "suggested, unverified")
## Summary (2-3 sentences)
## Affected endpoint
## Technical details (what the evidence shows, why it is a CRLF/header injection)
## Steps to reproduce (numbered; include a `curl -i` line)
## Chaining analysis (walk the realistic escalation paths from the candidates; for each say what to test to confirm and the expected impact if confirmed; flag the SSRF->RCE path only if the parameter is a server-side fetcher)
## Impact (only what evidence + a realistic, stated-as-unconfirmed chain supports)
## Remediation (strip/reject CR and LF in header-bound input; safe header APIs; redirect allowlists)
Return Markdown only, no preamble."""
    body = llm_call(prompt, provider, model, base_url).strip()
    if not body or "## " not in body:
        # deterministic fallback so a report always exists
        body = fallback_finding_md(f, chains)
    return body


def fallback_finding_md(f, chains):
    host = f.get("url", "")
    confirmed = bool(f.get("confirmed"))
    if confirmed:
        sev = ("Suggested (unverified): CVSS 3.1 AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N "
               "— base ~6.1 (Medium). Re-rate after confirming the chain.")
        summary = (f"The `{f.get('param')}` parameter reflects injected CR/LF into HTTP "
                   f"response headers (double-confirmed by the {f.get('engine')} engine).")
        tech = ("Injecting the payload below caused the token to appear in a response "
                "header, which shows the CR/LF was interpreted rather than encoded.")
        impact = ("Header-injection primitive confirmed. Higher impact (XSS, session "
                  "fixation, open redirect, cache poisoning, or SSRF->RCE) depends on the "
                  "chains above and must be demonstrated before it is claimed.")
        repro3 = "3. Repeat with a fresh token to rule out caching."
    else:
        sev = ("UNCONFIRMED LEAD — no severity until reproduced. Engine flag only; "
               "it may be a false positive.")
        summary = (f"The {f.get('engine')} engine flagged `{f.get('param')}` as a possible "
                   f"CRLF point. This is NOT confirmed — reproduce it by hand before trusting it.")
        tech = (f"The {f.get('engine')} engine reported this URL as a candidate. No "
                f"token-in-header reflection has been double-confirmed here; treat the "
                f"evidence below as a lead to verify, not proof.")
        impact = ("None established. This is an unverified lead; confirm the primitive in "
                  "Burp Repeater first, then assess impact.")
        repro3 = ("3. Confirm a unique token actually lands in a RESPONSE HEADER (not the "
                  "body). If it does not, this is a false positive.")
    return f"""## Title
CRLF / HTTP header injection in `{f.get('param')}`{'' if confirmed else '  (UNCONFIRMED)'}

## Severity
{sev}

## Summary
{summary}

## Affected endpoint
`{host}`

## Technical details
{tech}
Payload: `{f.get('payload')}`
Evidence:
```
{chr(10).join(f.get('evidence', [])) or '(none captured)'}
```

## Steps to reproduce
1. Send:
```bash
curl -i '{host}'
```
2. Observe the response headers.
{repro3}

## Chaining analysis
Candidate paths (confirm manually, in scope only): {', '.join(chains)}.

## Impact
{impact}

## Remediation
Reject or strip `\\r` and `\\n` from any value placed into a response header; use framework header APIs that encode control characters; use an allowlist for redirect targets."""


def overall_sections(findings, provider, model, base_url, target):
    confirmed = [f for f in findings if f.get("confirmed")]
    counts = {}
    for f in findings:
        counts[f.get("engine", "?")] = counts.get(f.get("engine", "?"), 0) + 1
    fetchers = [f for f in findings if looks_like_fetcher(f.get("param"))]
    prompt = f"""Write two Markdown sections for a CRLF-injection assessment report of {target}, AUTHORIZED test. Facts: {len(findings)} total findings, {len(confirmed)} double-confirmed, {len(fetchers)} on server-side-fetcher parameters (SSRF->RCE candidates), engines used: {list(counts)}. Do not overstate; confirmed means the header-injection primitive only, not full exploitation.
Return exactly:
## Executive summary (plain-language, 4-6 sentences: what was tested, what was found, the headline risk, and that exploitation/chaining still needs manual confirmation)
## Methodology (recon -> parameter discovery -> multi-engine CRLF fuzzing with double-confirmation -> chaining analysis -> this report; name the engines)
Markdown only."""
    text = llm_call(prompt, provider, model, base_url).strip()
    if "## Executive summary" not in text:
        text = (f"## Executive summary\n"
                f"An authorized CRLF / HTTP-header-injection assessment of {target} produced "
                f"{len(findings)} findings, {len(confirmed)} of them double-confirmed, with "
                f"{len(fetchers)} on parameters that look like server-side fetchers (SSRF->RCE "
                f"candidates). Confirmed findings establish the header-injection primitive only; "
                f"escalation to XSS, session fixation, open redirect, cache poisoning, or SSRF->RCE "
                f"still requires manual confirmation per the chaining notes.\n\n"
                f"## Methodology\n"
                f"Recon (subfinder, crt.sh, httpx) -> URL/param discovery (gau, katana) -> "
                f"multi-engine CRLF fuzzing (built-in token fuzzer, crlfuzz, CRLFsuite, nuclei) "
                f"with double-confirmation -> chaining analysis -> report generation.")
    return text


def build(workdir, provider="claude-code", model="llama3.1", base_url=None,
          target=None, tester="(tester)"):
    workdir = Path(workdir)
    findings = json.loads((workdir / "findings.json").read_text()) if (workdir / "findings.json").exists() else []
    triage = {}
    if (workdir / "triage.json").exists():
        try:
            triage = {int(k): v for k, v in json.loads((workdir / "triage.json").read_text()).items()}
        except (ValueError, AttributeError):
            triage = {}
    target = target or workdir.name.replace("crlf_", "")
    today = dt.date.today().isoformat()

    findings = sorted(findings, key=lambda f: (not f.get("confirmed"),
                      SEVERITY_ORDER.get((triage.get(findings.index(f), {}) or {}).get("severity", "-"), 5)))

    (workdir / "reports").mkdir(exist_ok=True)
    doc = [f"# CRLF Injection Assessment - {target}",
           f"_Tester: {tester} · Date: {today} · Authorized testing only_", "",
           "> DRAFT. Every proof-of-concept must be reproduced by hand before "
           "submission. Severities and chains are suggestions; confirm in scope first.", "",
           overall_sections(findings, provider, model, base_url, target), "",
           "## Findings at a glance", "",
           "| # | Severity (LLM) | Confirmed | Param | Host | Engine |",
           "|---|---|---|---|---|---|"]
    rows = []
    for i, f in enumerate(findings, 1):
        t = triage.get(i - 1, {}) or {}
        host = re.sub(r"^https?://", "", f.get("url", "")).split("/")[0]
        doc.append(f"| {i} | {t.get('severity','-')} | {f.get('confirmed')} | "
                   f"`{f.get('param')}` | {host} | {f.get('engine')} |")
        rows.append([i, t.get("severity", "-"), f.get("confirmed"), f.get("param"),
                     host, f.get("engine"), f.get("url")])
    doc.append("")

    for i, f in enumerate(findings, 1):
        t = triage.get(i - 1, {}) or {}
        md = per_finding_report(f, t, i, provider, model, base_url)
        doc += [f"\n---\n\n# Finding {i}", md, ""]
        (workdir / "reports" / f"finding_{i:02d}.md").write_text(
            f"# Finding {i} - {target}\n_Authorized test · {today} · DRAFT, validate before submitting_\n\n{md}\n")

    doc += ["\n---\n", "## References", ""]
    doc += [f"- {r}" for r in REFERENCES]
    doc += ["", "## Disclaimer",
            "Produced by an automated assistant from scan output. It is a drafting "
            "aid, not proof. Test only assets you are authorized to test, keep every "
            "action in scope, and reproduce each finding manually before reporting."]

    (workdir / "REPORT_FULL.md").write_text("\n".join(doc))
    with (workdir / "findings.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["#", "severity", "confirmed", "param", "host", "engine", "url"])
        w.writerows(rows)

    print(f"[*] report: {(workdir / 'REPORT_FULL.md').resolve()}")
    print(f"[*] per-finding: {(workdir / 'reports').resolve()}/  ·  csv: findings.csv")
    return workdir / "REPORT_FULL.md"


def main():
    ap = argparse.ArgumentParser(description="Build a detailed CRLF report from scan output")
    ap.add_argument("--dir", required=True, help="a crlf_<target> scan folder")
    ap.add_argument("--target")
    ap.add_argument("--tester", default="(tester)")
    ap.add_argument("--llm-provider", default="claude-code",
                    choices=["claude-code", "anthropic", "openai", "ollama"])
    ap.add_argument("--llm-base-url")
    ap.add_argument("--model", default="llama3.1")
    args = ap.parse_args()
    build(args.dir, args.llm_provider, args.model, args.llm_base_url,
          args.target, args.tester)


if __name__ == "__main__":
    main()
