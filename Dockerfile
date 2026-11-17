# ---- stage 1: build the Go recon/CRLF tools ----
FROM golang:1.23-bookworm AS tools
ENV GOBIN=/go/bin
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install github.com/projectdiscovery/katana/cmd/katana@latest \
 && go install github.com/lc/gau/v2/cmd/gau@latest \
 && go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest \
 && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# ---- stage 2: runtime ----
FROM python:3.12-slim-bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl jq ca-certificates git \
 && rm -rf /var/lib/apt/lists/*
COPY --from=tools /go/bin/ /usr/local/bin/

WORKDIR /opt/crlf-hunter
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && (pip install --no-cache-dir crlfsuite || echo "crlfsuite optional; skipped")
COPY . /opt/crlf-hunter
RUN cp /opt/crlf-hunter/entrypoint.sh /usr/local/bin/entrypoint.sh \
 && chmod +x /usr/local/bin/entrypoint.sh

# outputs + scope live here; mount a host dir to persist them
VOLUME /data
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["-h"]
