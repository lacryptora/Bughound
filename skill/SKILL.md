---
name: crlf-hunt
description: >-
  Hunt CRLF / HTTP header injection on an AUTHORIZED target, from recon through
  chaining to a report draft. Trigger when the user gives a domain, wildcard, or
  URL and asks to find CRLF injection, header injection, response splitting, or
  to run the CRLF hunter. Enforces a scope file and leaves exploitation and
  proof-of-concept validation to the human.
---

# crlf-hunt

A workflow for finding CRLF / HTTP-header-injection bugs on targets you are
authorized to test (your own assets, or a bug-bounty program whose scope you
have confirmed). It wraps `crlf_hunt.py` (in this skill folder) which runs
recon → parameter discovery → multi-engine CRLF fuzzing → double-confirm →
chaining analysis → LLM triage → report + playbook.

## Hard rules (do not skip)

1. **Authorization first.** Before running anything, confirm with the user that
   every host is in scope. Write the scope to `scope.txt`, one host per line
   (`*.` wildcards allowed). The tool refuses any host not in that file.
2. **Detect, don't weaponize.** The tool only confirms the primitive (a token
   reflected in a response header). It never auto-fires XSS, cache poisoning,
   or SSRF/RCE. Those stay in `playbook.md` as manual templates.
3. **Validate by hand.** Tell the user to reproduce every hit in Burp Repeater
   before reporting. LLM verdicts and engine flags are hints, not proof.

## Prerequisites

- Python: `pip3 install requests`
- Recon engines (optional but recommended), installed and on PATH:
  `subfinder`, `httpx`, `katana`, `gau` (ProjectDiscovery / tomnomnom tools).
- CRLF engines (optional, auto-used if present): `crlfuzz`, `crlfsuite`, `nuclei`.
- Keep `crlf_hunt.py` and `crlf_payloads.txt` together in the working directory.

## Steps

1. **Scope.** Ask for the target and its scope. Create `scope.txt`.
2. **Run.** From the folder holding the two files:
   ```bash
   python3 crlf_hunt.py -d TARGET.com --scope scope.txt           # domain + subdomains
   python3 crlf_hunt.py -d "*.TARGET.com" --scope scope.txt        # wildcard
   python3 crlf_hunt.py -u https://app.TARGET.com/p --scope scope.txt   # single URL
   ```
3. **SSRF reachability (optional).** If fetcher-like params exist (`url`,
   `redirect`, `callback`, `webhook`, `proxy`…), add your own OOB listener:
   ```bash
   python3 crlf_hunt.py -d TARGET.com --scope scope.txt --oob-url YOURID.oast.site
   ```
   Then watch that listener for the token in `oob_ssrf_probes.txt`.
4. **LLM triage.** Pick the provider the user has:
   - Claude Pro/Max login (no API key): first `claude` once to log in, then
     `--llm --llm-provider claude-code`
   - Free local model: `--llm --llm-provider ollama --model llama3.1`
   - OpenAI-compatible free endpoint: `--llm --llm-provider openai
     --llm-base-url <url> --model <model>` with `LLM_API_KEY` set
   - Paid Anthropic API key: `--llm --llm-provider anthropic --model claude-haiku-5-5`
5. **Read the output** in `crlf_TARGET/`:
   - `REPORT_FULL.md` — the detailed report, auto-built by `report_agent.py`
     when `--llm` is set (exec summary, methodology, every finding in full,
     references). Regenerate anytime: `python3 report_agent.py --dir
     crlf_TARGET --target TARGET --llm-provider claude-code`
   - `reports/finding_NN.md` — standalone HackerOne-style writeup per finding
   - `findings.csv` — tracking table
   - `playbook.md` — the chaining guide (see below)
   - `report.md` / `findings.json` / `triage.json` — short report + raw data
   - `params.txt`, `oob_ssrf_probes.txt`, per-engine output files
6. **Hand back** the confirmed findings, the best chain per finding, and the
   explicit reminder to validate manually and stay in scope.

## Chaining (what `playbook.md` covers)

For each double-confirmed CRLF point, the tool maps escalation paths with
manual PoC templates:

- CRLF → response splitting → **XSS**
- CRLF → **Set-Cookie** → session fixation
- CRLF → **Location** → open redirect → OAuth token theft / account takeover
- CRLF → response splitting → **web cache poisoning** (mass impact; only if the
  program permits cache attacks)
- CRLF → **SSRF → RCE** via gopher/redis/dict protocol injection — only when the
  sink is a server-side fetcher (same class as the GitLab `git://` → Redis case).
  Prove SSRF with the OOB probe first; craft the gopher/redis payload by hand,
  only against in-scope infra with explicit permission, never third-party or
  out-of-scope internal hosts.

## Flags reference

- `-d` domain/wildcard · `-u` single URL · `--scope` required scope file
- `--payloads` custom list (default `crlf_payloads.txt`; `{T}` = token slot)
- `--engines builtin,crlfuzz,crlfsuite,nuclei` · `--delay` · `--max-tests`
- `--oob-url` safe SSRF reachability probe to your own listener
- `--llm` + `--llm-provider {claude-code,anthropic,openai,ollama}` + `--model`

## Payload sources folded into `crlf_payloads.txt`

payload-box (250+), PortSwigger, CRLFsuite, Proviesec, PayloadsAllTheThings —
covering basic sequences, whitespace/tab, double/triple encoding, UTF-8 and
Firefox-strip (嘊嘍) tricks, unicode, null bytes, special-char prefixes,
path-based, and Set-Cookie variants. To add the full payload-box list, convert
its marker to the token: `sed 's/MARKER/{T}/g' list.txt > extra.txt` then
`--payloads extra.txt`.
