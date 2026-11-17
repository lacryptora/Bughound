#!/usr/bin/env python3
"""
triage_hosts.py: AI triage for attack-surface / exposed-interface discovery.

Feed it httpx output (URL + status + title + content-length + tech). It asks an
LLM to classify each live host as REVIEW (a likely exposed app/internal
interface worth a manual look for an access-control-bypass report) or SKIP
(login-only page, generic/placeholder, firewall/WAF block, 401/403). It writes
a ranked hosts_triage.md and prints the REVIEW candidates.

This fits programs like FloQast whose rule is: report a public host that returns
200 with real functional content or an internal interface — NOT generic pages or
firewall blocks.

Make the input first:
  subfinder -d target.com -all -silent | httpx -silent -sc -title -cl -td -o live.txt

Then:
  python3 triage_hosts.py --in live.txt --target target.com --llm-provider claude-code

Providers: claude-code (your Pro login, no API key) | anthropic | openai | ollama.
Only decides what deserves a manual look — it never bypasses anything itself.
"""
import argparse
import json
import os
import re
import subprocess
from pathlib import Path

import requests

BATCH = 35  # hosts per LLM call


def llm_call(prompt, provider, model, base_url):
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
                json={"model": model, "max_tokens": 2000,
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


def llm_json_array(prompt, provider, model, base_url):
    text = llm_call(prompt, provider, model, base_url)
    m = re.search(r"\[.*\]", text, re.S)
    if m:
        try:
            return json.loads(m.group(0))
        except ValueError:
            pass
    return []


def triage_batch(lines, provider, model, base_url, target):
    joined = "\n".join(lines)
    prompt = f"""You are triaging subdomain-discovery results for an AUTHORIZED bug bounty on {target}.
The program rewards ONLY a public host that exposes functional application data or an INTERNAL interface (an access-control bypass). It explicitly does NOT reward: a login page by itself, generic/placeholder/marketing content, firewall/WAF block pages, 401/403, or empty responses.

For each host line below (httpx output: URL, [status], [title], [content-length], [tech]), decide:
- verdict: "review" if it plausibly exposes an internal tool, dashboard, admin panel, API, dev/staging app, monitoring (Grafana/Kibana/Jenkins/etc.), or functional data worth a manual look; "skip" otherwise.
- type: a short guess of what it is (e.g. "Grafana", "login page", "WAF block", "marketing", "API").
- reason: one short clause.

Hosts:
{joined}

Return ONLY a JSON array, one object per host, in the same order:
[{{"host":"<url>","verdict":"review|skip","type":"...","reason":"..."}}]"""
    return llm_json_array(prompt, provider, model, base_url)


def main():
    ap = argparse.ArgumentParser(description="AI triage for exposed-interface discovery")
    ap.add_argument("--in", dest="inp", required=True, help="httpx output file")
    ap.add_argument("--target", default="the target")
    ap.add_argument("--llm-provider", default="claude-code",
                    choices=["claude-code", "anthropic", "openai", "ollama"])
    ap.add_argument("--llm-base-url")
    ap.add_argument("--model", default="llama3.1")
    args = ap.parse_args()

    lines = [l.strip() for l in Path(args.inp).read_text().splitlines() if l.strip()]
    if not lines:
        raise SystemExit("[!] input is empty")
    print(f"[*] {len(lines)} live hosts to triage ({args.llm_provider})")

    results = []
    for i in range(0, len(lines), BATCH):
        batch = lines[i:i + BATCH]
        print(f"[*] batch {i // BATCH + 1} ({len(batch)} hosts)...")
        res = triage_batch(batch, args.llm_provider, args.model, args.llm_base_url, args.target)
        if len(res) != len(batch):
            # LLM unavailable or malformed -> keep the raw lines as 'review' so
            # nothing is silently dropped; you still see them to check by hand.
            res = [{"host": l.split()[0] if l.split() else l, "verdict": "review",
                    "type": "?", "reason": "not triaged (LLM unavailable) - review manually"}
                   for l in batch]
        results.extend(res)

    review = [r for r in results if str(r.get("verdict", "")).lower() == "review"]
    skip = [r for r in results if str(r.get("verdict", "")).lower() != "review"]

    out = [f"# Exposed-interface triage - {args.target}", "",
           "> Candidates to open in a browser. A VALID report needs you to reach "
           "functional app data or an internal interface - a login page or block "
           "page alone is not enough. Authorized testing only.", "",
           f"## Review first ({len(review)})", ""]
    for r in review:
        out.append(f"- [ ] **{r.get('host')}** — _{r.get('type','?')}_ — {r.get('reason','')}")
    out += ["", f"## Skipped ({len(skip)})", ""]
    for r in skip:
        out.append(f"- {r.get('host')} — {r.get('type','?')} — {r.get('reason','')}")
    Path("hosts_triage.md").write_text("\n".join(out))

    print(f"\n[*] {len(review)} to REVIEW, {len(skip)} skipped -> hosts_triage.md")
    for r in review:
        print(f"    [REVIEW] {r.get('host')}  ({r.get('type','?')})  {r.get('reason','')}")


if __name__ == "__main__":
    main()
