# ─────────────────────────────────────────────────────────────────
# ReconHawk – Dockerfile
# Bundles Python tool + Nikto + Nuclei in a single container.
# Build : docker build -t reconhawk .
# Run   : docker run --rm reconhawk -t example.com --html
# ─────────────────────────────────────────────────────────────────

FROM python:3.11-slim

LABEL maintainer="ReconHawk" \
      description="Automated Reconnaissance & Vulnerability Scanner"

# ── System deps ────────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget git perl libssl-dev nmap dnsutils whois \
    && rm -rf /var/lib/apt/lists/*

# ── Nikto ──────────────────────────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl

# ── Nuclei ─────────────────────────────────────────────────────────────────────
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then GOARCH="amd64"; else GOARCH="arm64"; fi && \
    curl -sL "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_${GOARCH}.zip" \
         -o /tmp/nuclei.zip && \
    unzip -q /tmp/nuclei.zip -d /usr/local/bin/ && \
    rm /tmp/nuclei.zip && \
    chmod +x /usr/local/bin/nuclei

# Update Nuclei templates
RUN nuclei -update-templates -silent || true

# ── Python deps ────────────────────────────────────────────────────────────────
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Application code ──────────────────────────────────────────────────────────
COPY . .

# ── Output directory ──────────────────────────────────────────────────────────
RUN mkdir -p /app/reports
VOLUME ["/app/reports"]

# ── Entrypoint ────────────────────────────────────────────────────────────────
ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
