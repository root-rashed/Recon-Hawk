# ⚡ ReconHawk

**Automated Reconnaissance & Vulnerability Scanner**

> A modular, CLI-based security assessment tool that automates the full recon → crawl → vuln-scan → report workflow against authorized web targets.

---

## ⚠️ Legal Notice

**Use only on systems you own or have explicit written permission to test.**
Unauthorized scanning is illegal in most jurisdictions. The authors accept no
liability for misuse.

---

## Features

| Module | Capabilities |
|--------|-------------|
| **Recon** | DNS enumeration, subdomain brute-force + crt.sh, HTTP header analysis, technology fingerprinting, port scanning with banner grabbing, WHOIS |
| **Crawler** | Recursive BFS crawling (configurable depth), JS file extraction, parameter discovery, form enumeration, interesting-path probing, secret pattern detection |
| **Vuln Scanner** | 15+ custom checks + Nikto integration + Nuclei integration |
| **Reporter** | JSON report (always), HTML report (optional), AI-assisted executive summary (optional) |

### Vulnerability Checks (Custom)

- Security headers audit (HSTS, CSP, X-Frame-Options, etc.)
- CORS misconfiguration
- Clickjacking
- Cookie flag analysis (Secure / HttpOnly / SameSite)
- Information disclosure (.env, .git, phpinfo, actuator, etc.)
- Dangerous HTTP methods (TRACE, PUT, DELETE)
- SSL/TLS enforcement
- Directory listing
- Default credentials
- Open redirect
- SQL injection (error-based)
- Reflected XSS
- XXE injection
- SSRF
- Local File Inclusion

### Bonus Features

- ✅ Recursive crawling (configurable depth)
- ✅ Multi-threading / async processing
- ✅ Smart deduplication of results
- ✅ HTML report generation (dark-mode, professional)
- ✅ Docker support
- ✅ AI-assisted executive summary (Claude API)
- ✅ Stealth / rate-limiting options

---

## Installation

### Option 1 – Local (Python 3.10+)

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/reconhawk.git
cd reconhawk

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt

# (Optional) Install Nikto
sudo apt install nikto          # Debian/Ubuntu
# or: brew install nikto        # macOS

# (Optional) Install Nuclei
# Download from https://github.com/projectdiscovery/nuclei/releases
# and place in PATH, then update templates:
nuclei -update-templates
```

### Option 2 – Docker (recommended for clean environment)

```bash
# Build the image (includes Nikto + Nuclei)
docker build -t reconhawk .

# Run a scan
docker run --rm -v $(pwd)/reports:/app/reports reconhawk \
  -t example.com --html

# With AI summary
docker run --rm \
  -v $(pwd)/reports:/app/reports \
  -e ANTHROPIC_API_KEY=sk-ant-... \
  reconhawk -t example.com --html --ai-summary
```

---

## Usage

```
python main.py -t <TARGET> [OPTIONS]
```

### Required

| Argument | Description |
|----------|-------------|
| `-t, --target` | Domain, subdomain, URL, or IP address |

### Scan Options

| Argument | Default | Description |
|----------|---------|-------------|
| `--ports` | Common web ports | Comma-separated ports or range (e.g. `80,443,8080` or `1-1000`) |
| `--threads` | `10` | Number of concurrent threads |
| `--depth` | `2` | Crawling depth (recursion level) |
| `--timeout` | `10` | Request timeout in seconds |
| `--rate-limit` | `0.1` | Delay between requests (seconds) – stealth control |
| `--user-agent` | ReconHawk UA | Custom User-Agent string |

### Module Toggles

| Argument | Description |
|----------|-------------|
| `--skip-recon` | Skip reconnaissance phase |
| `--skip-crawl` | Skip crawling phase |
| `--skip-vuln` | Skip all vulnerability scanning |
| `--skip-nikto` | Skip Nikto (run custom checks + Nuclei only) |
| `--skip-nuclei` | Skip Nuclei (run custom checks + Nikto only) |

### Output Options

| Argument | Description |
|----------|-------------|
| `--output-dir` | Output directory for reports (default: `./reports`) |
| `--html` | Generate HTML report |
| `--ai-summary` | Generate AI executive summary (requires `ANTHROPIC_API_KEY`) |
| `--quiet, -q` | Suppress banner and verbose output |
| `--no-color` | Disable ANSI colour codes |

---

## Examples

```bash
# Basic scan
python main.py -t example.com

# Full scan with HTML report
python main.py -t example.com --html

# Aggressive (more ports, deeper crawl)
python main.py -t 192.168.1.1 --ports 1-65535 --depth 4 --threads 20

# Stealth (slow, polite)
python main.py -t example.com --rate-limit 1.0 --threads 3

# Skip external scanners, custom checks only
python main.py -t example.com --skip-nikto --skip-nuclei

# Full report with AI summary
export ANTHROPIC_API_KEY=sk-ant-xxxxx
python main.py -t example.com --html --ai-summary

# Quick recon only (no crawl, no vuln scan)
python main.py -t example.com --skip-crawl --skip-vuln
```

---

## Architecture

```
reconhawk/
├── main.py                  # CLI entry point & phase orchestration
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
│
├── modules/
│   ├── recon.py             # Reconnaissance (DNS, subdomains, ports, headers)
│   ├── crawler.py           # Web crawling (BFS, JS analysis, forms)
│   ├── vuln_scanner.py      # Vuln scanning (custom + Nikto + Nuclei)
│   └── report_generator.py  # JSON / HTML / AI report
│
├── utils/
│   ├── console.py           # Coloured terminal output
│   ├── validator.py         # Target validation & normalisation
│   └── http_client.py       # Shared requests session helper
│
└── reports/                 # Generated reports (gitignored except sample)
    └── sample_report_testphp_vulnweb_com.json
```

---

## Report Format

### JSON (`report_<host>_<timestamp>.json`)

Top-level keys:

```json
{
  "meta":  { "target": {...}, "start_time": "...", "end_time": "..." },
  "recon": { "dns": {...}, "subdomains": [...], "open_ports": [...], ... },
  "crawl": { "urls": [...], "js_files": [...], "parameters": [...], ... },
  "vulns": {
    "critical": [...],
    "high":     [...],
    "medium":   [...],
    "low":      [...],
    "info":     [...]
  }
}
```

Each finding object:

```json
{
  "title":       "Potential SQL Injection",
  "severity":    "high",
  "description": "SQL error message visible in response...",
  "url":         "https://example.com/page?id=1'",
  "evidence":    "You have an error in your SQL syntax...",
  "tool":        "custom | nikto | nuclei",
  "cwe":         "CWE-89",
  "remediation": "Use parameterised queries."
}
```

### HTML Report

Dark-mode, fully self-contained HTML with:
- Statistics bar (finding counts by severity)
- Target information card
- Technology badges
- Sortable findings table
- Subdomain list, open ports, DNS records
- Crawl results (URLs, JS files, parameters)

---

## AI Summary (Bonus)

Set `ANTHROPIC_API_KEY` and pass `--ai-summary`. The tool sends an aggregated
summary of findings to Claude (claude-opus-4-5) and receives a professional
executive summary including risk assessment, key concerns, and top 3 recommended
actions.

---

## External Tool Integration

### Nikto

ReconHawk runs Nikto with broad coverage tuning flags:

```
nikto -h <host> -p <port> -Tuning x6789abc -Format txt -nointeractive
```

Output is parsed line-by-line and classified into severity levels based on
keyword heuristics (OSVDB IDs, CVE references, etc.).

### Nuclei

ReconHawk runs Nuclei with template categories:

```
nuclei -u <url> -j -severity info,low,medium,high,critical \
       -t cves/ -t vulnerabilities/ -t misconfiguration/ \
       -t exposures/ -t technologies/ -rate-limit 10
```

JSONL output is parsed and each finding is ingested as a `Finding` object.

---

## Tested Environments

- Python 3.10 / 3.11 / 3.12
- Ubuntu 22.04 / 24.04
- macOS 13+
- Docker 24+

---

## Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feat/my-check`)
3. Add your module or check with proper docstrings
4. Submit a Pull Request

---

## License
MIT License

Copyright (c) 2026 ReconHawk

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
