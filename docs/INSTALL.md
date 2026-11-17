# Install

Works on Linux, WSL+Ubuntu on Windows, or Kali. WSL+Ubuntu is the lightest;
Kali is worth it only if you also want its preinstalled pentest tools.

## 1. Base system

### WSL + Ubuntu (Windows)
In PowerShell as Administrator:
```powershell
wsl --install
```
Open **Ubuntu**, set a username/password, then continue inside Ubuntu.

### Kali (or any Linux)
Open a terminal and continue below. Everything is identical.

## 2. Python + Go + basics
```bash
sudo apt update
sudo apt install -y python3 python3-pip golang-go curl jq git dos2unix
echo 'export PATH=$PATH:$HOME/go/bin:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```
If `apt`'s Go is older than 1.21, install the current Go from https://go.dev/dl
instead (the README's INSTALL route via nodesource is only for Node).

## 3. Project deps
```bash
cd crlf-hunter
pip3 install -r requirements.txt       # just: requests
bash install.sh                        # external recon/CRLF tools
```

`install.sh` installs: subfinder, httpx, katana, gau (recon) and crlfuzz
(CRLF). CRLFsuite and nuclei are optional extras it will try too. Any tool
that fails is simply skipped at runtime — the built-in fuzzer always works.

Manual equivalents if you prefer:
```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest
pipx install crlfsuite        # or: pip3 install crlfsuite
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

## 4. The AI agent

Pick ONE:

### A. Claude Pro/Max (no API key) — recommended if you have it
```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
npm install -g @anthropic-ai/claude-code
claude          # logs in via your Windows browser; choose the subscription login, then /exit
```
Do the `claude` login **in the same environment** (same WSL/Kali) you run the
scan from. Then use `--llm-provider claude-code`.

Note: a Claude Pro/Max subscription is **not** the same as an API key. It works
here because the Claude Code CLI carries your subscription session; the script
calls `claude -p` as a subprocess.

### B. Free local model
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.1
```
Then `--llm-provider ollama --model llama3.1`.

### C. Free OpenAI-compatible endpoint (OpenRouter free, Groq, Gemini-compat)
```bash
export LLM_API_KEY="your-free-key"
```
Then `--llm-provider openai --llm-base-url https://openrouter.ai/api/v1 --model <model>`.

### D. Paid Anthropic API
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```
Then `--llm-provider anthropic --model claude-haiku-5-5`.

## 5. Optional: subfinder & gau API keys (more subdomains/URLs)
```bash
mkdir -p ~/.config/subfinder
nano ~/.config/subfinder/provider-config.yaml   # add github/virustotal/chaos keys
chmod 600 ~/.config/subfinder/provider-config.yaml
```
See each tool's docs for the key format. Everything runs without keys too.

## 6. Copy the scripts (if coming from Windows)
```bash
cp /mnt/c/Users/YOURNAME/Downloads/crlf-hunter -r ~/crlf-hunter   # adjust path
cd ~/crlf-hunter
dos2unix *.sh *.py 2>/dev/null
chmod +x install.sh
```

## Verify
```bash
python3 crlf_hunt.py -h
python3 report_agent.py -h
```
