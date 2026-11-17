---
name: js-analysis
description: >-
  Analyze an AUTHORIZED target's JavaScript for hidden endpoints, API paths,
  leaked secrets/API keys, exposed source maps, and DOM-XSS sinks. Trigger when
  asked to analyze JS, find endpoints/secrets in JS, or run the jsrecon module.
  Especially for SPA targets where normal recon finds few params.
---

# js-analysis

Modern apps (SPAs, dashboards) hide their real attack surface in JavaScript —
API endpoints the page calls, feature flags, and sometimes hardcoded secrets.
This is the fix for "recon found 0 params": the params live in the JS. Uses
`js_recon.py` (shared scope).

## Hard rules
1. Scope enforced via `scope.txt`. Reading JS is passive.
2. A found secret must be **validated, then reported** — NEVER used. Using a live
   key is illegal and off-limits. Validate per the api-key-leaks methodology
   (keyhacks / the service's own docs), then report.

## Run
```bash
python3 js_recon.py -d target.com --scope scope.txt
python3 js_recon.py --js-list jsfiles.txt --scope scope.txt   # analyze a known list
python3 hunt.py -d "*.target.com" --scope scope.txt --modules jsrecon
```
Outputs: `js_endpoints.txt`, `js_findings.json`, `report_jsrecon.md`.

## What it mines
- **Endpoints / API paths** → feed back into the CRLF/open-redirect/xss modules
  (`--params-file js_endpoints.txt`) to test the real API surface.
- **Secrets** (high-confidence: AWS/Google/GitHub/Stripe/Slack keys, JWTs, private
  keys; medium: generic api_key patterns). High-confidence = report-worthy.
- **Exposed source maps** (`.map`) → near-original source, far easier to audit.
- **DOM-XSS sinks** (+ co-located sources) → leads for the xss skill.

## The high-value workflow for SPA targets
1. `js_recon.py` → endpoints + secrets + source maps + sink leads.
2. **Check source maps first** — if `.map` is exposed, download it; you get
   near-original source (readable), which makes everything else easier.
3. Feed `js_endpoints.txt` to the param-based modules to test the hidden API:
   `python3 hunt.py -u https://target --scope scope.txt --modules crlf,open-redirect,xss --params-file js_endpoints.txt` (or run crlf_hunt with --params-file).
4. Validate any secret with keyhacks; if live and in scope, report it.
5. Investigate sink leads per the xss skill.

## Deeper JS (webpack chunks, lazy-loaded)
Minified webpack bundles reference lazy-loaded chunks by id+hash. To pull them all:
jsluice, or community tools (jxscout, dechunker.js, diffscript). Monitoring JS over
time (gregxsunday/Kanshi approach) catches new endpoints as the app ships them.
`js_recon.py` extracts from whatever JS it is given — point it at downloaded chunks
for full coverage.

## Why this matters
On path-based SPAs (luxury retail, dashboards) the CRLF/redirect/xss modules find
nothing from URLs alone — the parameters are in the JS-defined API calls. This
module surfaces them, turning a "0 params" dead end into a real test surface. It
also finds the single highest-ROI beginner bug: a **leaked live API key**.
