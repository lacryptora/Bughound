# Usage

## Scope file (required)
One host per line; `*.` wildcards allowed. Anything not matching is skipped.
```
target.com
*.target.com
app.target.com
```

## Flags
```
-d, --domain        domain or wildcard (recon includes subdomains)
-u, --url           single URL (that host only)
--scope             scope file (required)
--payloads          payload list (default crlf_payloads.txt; {T} = token slot)
--delay             seconds between requests (default 1.0; raise to be gentle)
--max-tests         cap on built-in requests (default 3000)
--engines           comma list: builtin,crlfuzz,crlfsuite,nuclei
--oob-url           your OWN listener host for a safe SSRF-reachability probe
--llm               run AI triage + auto-build the full report
--llm-provider      claude-code | anthropic | openai | ollama
--llm-base-url      OpenAI-compatible base URL (openai/ollama providers)
--model             model name
```

## Recipes

Fast pass, one URL, no AI:
```bash
python3 crlf_hunt.py -u https://app.target.com/p?next=x --scope scope.txt
```

Whole scope, AI triage + full report via your Pro login:
```bash
python3 crlf_hunt.py -d target.com --scope scope.txt --llm --llm-provider claude-code
```

Add the safe SSRF reachability probe (needs a listener — Burp Collaborator or
`interactsh-client`), then watch it for the tokens logged in `oob_ssrf_probes.txt`:
```bash
python3 crlf_hunt.py -d target.com --scope scope.txt \
    --oob-url YOURID.oast.site --llm --llm-provider claude-code
```

Gentle + bounded (avoid hammering):
```bash
python3 crlf_hunt.py -d target.com --scope scope.txt --delay 2 --max-tests 1500
```

Only certain engines:
```bash
python3 crlf_hunt.py -d target.com --scope scope.txt --engines builtin,nuclei
```

Bigger payload list (convert any marker to the token first):
```bash
sed 's/BLATRUC/{T}/g' payload-box-list.txt > extra.txt
python3 crlf_hunt.py -d target.com --scope scope.txt --payloads extra.txt
```

Name yourself on the report:
```bash
TESTER="Scheima" python3 crlf_hunt.py -d target.com --scope scope.txt --llm --llm-provider claude-code
```

## How a hit is decided
The built-in fuzzer injects a payload carrying a unique token into each
parameter. A **hit** = that token appears in a response **header** (name or
value) — proof the CR/LF was interpreted, not body reflection. Each hit is then
re-sent with a fresh token; passing twice marks it `confirmed`. Engine findings
(crlfuzz/CRLFsuite/nuclei) are reported as `confirmed: false` until you
reproduce them.

## Manual tools (for validation)
```bash
crlfsuite -t "https://target/page?param=x"      # per-URL fuzz with PoCs
crlfuzz  -u "https://target/page?param=x"        # fast single-URL check
nuclei   -l params.txt -tags crlf                # template scan
```
Then confirm in Burp Repeater (Headers tab), with "Update Content-Length" off
when you edit the body.
