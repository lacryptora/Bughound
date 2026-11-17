# CRLF-Hunter — Command Cheat Sheet

Authorized testing only. Every host is filtered against a `scope.txt`
(allow lines + `!` exclusions). Reproduce every finding by hand before reporting.

---

## 0. One-time setup (WSL/Ubuntu or Kali)

```bash
# system + Go tools
sudo apt update && sudo apt install -y golang-go curl jq git dos2unix tmux
echo 'export PATH=$PATH:$HOME/go/bin:/usr/local/go/bin' >> ~/.bashrc && source ~/.bashrc

# recon + CRLF engines
bash install.sh                       # subfinder, httpx, katana, gau, crlfuzz, nuclei
go install github.com/tomnomnom/waybackurls@latest
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
pipx install crlfsuite                 # or: pip3 install --user crlfsuite

# python deps
pip3 install -r requirements.txt --break-system-packages    # requests, dnspython

# AI agent (Claude Pro login, no API key)
npm install -g @anthropic-ai/claude-code
claude          # /login -> choose subscription, then /exit
```

Fix line endings after copying from Windows: `dos2unix *.py *.sh *.txt`

---

## 1. Scope file

One host per line. `*.` = wildcard. `!` = exclude (out of scope).
Ready-made: `scope.uber.txt`, `scope.telekom.txt`, `scope.remitly.txt`.

```
*.target.com
!internal.target.com      # out of scope
```

---

## 2. ONE command — the unified runner (recommended)

Recon once, all modules, one merged report.

```bash
python3 hunt.py -d "*.target.com" --scope scope.target.txt \
    --modules crlf,open-redirect,hosts,takeover \
    --canary YOUR-CANARY.com \
    --oob-url YOURID.oast.live \
    --llm --llm-provider claude-code \
    --no-crawl --delay 1
```

Modules: `crlf | open-redirect | hosts | takeover`
Output: `hunt_<target>/report.md` (+ hosts_triage.md, report_takeover.md)

Crawl depth:
- `--no-crawl`  = archives only (fast; big targets)
- *(default)*   = archives + crawl first 60 hosts
- `--crawl-all` = archives + crawl EVERY host in batches (holistic, slow — use tmux)

---

## 3. Individual tools (run a single bug class)

### CRLF
```bash
python3 crlf_hunt.py -d "*.target.com" --scope scope.target.txt \
    --engines builtin,crlfuzz,crlfsuite,nuclei \
    --oob-url YOURID.oast.live \
    --delay 0.3 --max-tests 200000            # detect only; triage after
```
Resume a saved params file (skip recon):
```bash
python3 crlf_hunt.py -d "*.target.com" --scope scope.target.txt \
    --params-file crlf_target.com/params.txt --delay 0.3 --max-tests 200000
```
Every hit saves to `findings_builtin.json` as it is found (Ctrl+C safe).

### Open redirect
```bash
python3 open_redirect.py -d "*.target.com" --scope scope.target.txt \
    --canary YOUR-CANARY.com --llm --llm-provider claude-code --no-crawl
```

### Subdomain takeover
```bash
python3 subdomain_takeover.py --in crlf_target.com/subs.txt --scope scope.target.txt
# or enumerate + check:
python3 subdomain_takeover.py -d target.com --scope scope.target.txt
```

### Exposed-interface discovery
```bash
subfinder -d target.com -all -silent | httpx -silent -sc -title -cl -td -o live_detail.txt
python3 triage_hosts.py --in live_detail.txt --target target.com --llm-provider claude-code
```

---

## 4. Triage AFTER detection (saves Pro quota)

Run big scans WITHOUT `--llm`, then triage the saved findings once:
```bash
cd crlf_target.com
cp findings_builtin.json findings.json
python3 ../report_agent.py --dir . --target target.com \
    --tester "Scheima" --llm-provider claude-code
```
Produces `REPORT_FULL.md` + `reports/finding_NN.md` (HackerOne-style drafts).

---

## 5. Long runs — use tmux

```bash
tmux new -s hunt          # start
#   Ctrl+b then d         = detach (keeps running)
tmux attach -t hunt       # reattach
#   Ctrl+b then c         = new window (run a second tool in parallel)
```

---

## 6. Read results first

```bash
grep -l '"confirmed": true' */findings*.json   # which hosts had a real hit
cat hunt_target.com/report.md | head -60
cat */report_takeover.md 2>/dev/null
cat */hosts_triage.md 2>/dev/null
```
Open in Windows: `explorer.exe .`

Priority order for a FIRST bounty: **takeover -> exposed hosts -> open redirect -> crlf.**

---

## 7. The two active targets

### Uber (fast delay OK)
```bash
for t in "*.uber.com" "*.ubereats.com" "*.uberinternal.com"; do
  python3 hunt.py -d "$t" --scope scope.uber.txt \
    --modules crlf,open-redirect,hosts,takeover \
    --canary YOUR-CANARY.com --oob-url YOURID.oast.live \
    --crawl-all --crawl-cap 80 --delay 0.3 --max-tests 200000
done
# triage after, per target, to save quota
```

### Deutsche Telekom (strict RoE — keep delay high, benign PoCs only)
```bash
for t in "*.telekom.de" "*.telekom.net" "*.telekom.com" "*.t-systems.com"; do
  python3 hunt.py -d "$t" --scope scope.telekom.txt \
    --modules hosts,takeover,open-redirect \
    --canary YOUR-CANARY.com \
    --crawl-all --crawl-cap 80 --delay 2
done
```
Telekom: do NOT access data, do NOT affect availability, benign PoC only.
Submit via the "send us your report" link on their bug bounty page; CVSS 4.0.

---

## Reminders
- Confirm every hit by hand in Burp before reporting.
- `confirmed: true` with a real injected header = worth Burp. A `Location:` reflection = false positive.
- Don't inflate severity. Claim only what you demonstrated.
- Chains (OAuth->ATO, SSRF, cache poisoning) are manual, in scope only.
