# The AI report agent

`report_agent.py` turns scan output into a complete report. It runs
**automatically** at the end of a scan when `--llm` is set, and can also be run
standalone on any existing `crlf_<target>/` folder.

## What it produces

In the scan folder:

- **`REPORT_FULL.md`** — the main report:
  - Title, tester, date, draft banner
  - **Executive summary** (plain language)
  - **Methodology** (recon → params → multi-engine fuzz → confirm → chaining → report)
  - **Findings at a glance** table
  - **Every finding in full**: title, suggested CVSS, summary, affected
    endpoint, technical details, numbered steps to reproduce (with a `curl -i`),
    chaining analysis, impact, remediation
  - References (OWASP, CWE-93/113, PortSwigger, the GitLab SSRF→RCE case)
  - Disclaimer
- **`reports/finding_NN.md`** — one standalone, HackerOne-ready writeup per
  finding, so you can paste a single bug into a report form.
- **`findings.csv`** — a tracking table (#, severity, confirmed, param, host,
  engine, url).

## Run it standalone
```bash
python3 report_agent.py --dir crlf_target.com --target target.com \
    --tester "your name" --llm-provider claude-code
```
Same provider flags as `crlf_hunt.py` (`claude-code`, `anthropic`, `openai`,
`ollama`, plus `--llm-base-url`, `--model`).

## How it stays honest
- The **evidence, payloads, and PoCs are filled in deterministically** from the
  scan data. If the LLM is unavailable or returns junk, each finding falls back
  to a complete template — the report is never empty or fabricated.
- The LLM writes the **narrative** (summary, technical explanation, chaining
  walk-through, remediation) and a **suggested** CVSS, explicitly labelled
  unverified.
- Prompts forbid claiming impact beyond the demonstrated evidence; unproven
  escalation is marked "candidate / requires manual confirmation".
- The whole report carries a DRAFT banner: reproduce every PoC by hand, in
  scope, before submitting.

## Tuning
- Set your name on every report: `TESTER="Scheima" python3 crlf_hunt.py ...` or
  `--tester` on `report_agent.py`.
- Findings are ordered confirmed-first, then by LLM severity.
- To regenerate after editing `findings.json`/`triage.json`, just re-run
  `report_agent.py` on the folder.
