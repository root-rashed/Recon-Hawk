"""
modules/report_generator.py - Report generation module for ReconHawk.

Generates:
  - JSON report (always)
  - HTML report (--html flag)
  - AI-assisted summary (--ai-summary flag, requires ANTHROPIC_API_KEY)
"""

import json
import os
import re
from datetime import datetime

from utils.console import Console


class ReportGenerator:
    """Serialises scan results into structured reports."""

    def __init__(self, results: dict, output_dir: str,
                 generate_html: bool = False, ai_summary: bool = False):
        self.results       = results
        self.output_dir    = output_dir
        self.generate_html = generate_html
        self.ai_summary    = ai_summary
        self.timestamp     = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.target_host   = results["meta"]["target"]["host"].replace(".", "_")

    # ── Public entry point ────────────────────────────────────────────────────

    def generate(self) -> dict:
        paths = {}

        # Always generate JSON
        json_path = self._write_json()
        paths["json"] = json_path
        Console.success(f"JSON report saved: {json_path}")

        # Optional HTML
        if self.generate_html:
            html_path = self._write_html()
            paths["html"] = html_path
            Console.success(f"HTML report saved: {html_path}")

        # Optional AI summary
        if self.ai_summary:
            summary = self._generate_ai_summary()
            if summary:
                summary_path = self._write_text(summary, "ai_summary")
                paths["ai_summary"] = summary_path
                Console.success(f"AI summary saved: {summary_path}")

        return paths

    # ── JSON report ───────────────────────────────────────────────────────────

    def _write_json(self) -> str:
        filename = f"report_{self.target_host}_{self.timestamp}.json"
        path     = os.path.join(self.output_dir, filename)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.results, fh, indent=2, default=str)
        return path

    # ── Text file helper ──────────────────────────────────────────────────────

    def _write_text(self, content: str, suffix: str) -> str:
        filename = f"report_{self.target_host}_{self.timestamp}_{suffix}.txt"
        path     = os.path.join(self.output_dir, filename)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return path

    # ── HTML report ───────────────────────────────────────────────────────────

    def _write_html(self) -> str:
        filename = f"report_{self.target_host}_{self.timestamp}.html"
        path     = os.path.join(self.output_dir, filename)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self._build_html())
        return path

    def _build_html(self) -> str:
        meta    = self.results["meta"]
        recon   = self.results.get("recon", {})
        crawl   = self.results.get("crawl", {})
        vulns   = self.results.get("vulns", {})
        target  = meta["target"]

        # Count findings
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        all_findings = []
        for sev, items in vulns.items():
            if isinstance(items, list):
                counts[sev] = len(items)
                all_findings.extend(items)

        total_vulns = sum(counts.values())

        # Finding rows HTML
        finding_rows = ""
        sev_colors = {
            "critical": "#ff2d55",
            "high":     "#ff6b35",
            "medium":   "#ffd60a",
            "low":      "#30d158",
            "info":     "#636366",
        }
        for f in all_findings:
            sev   = f.get("severity", "info")
            color = sev_colors.get(sev, "#636366")
            finding_rows += f"""
            <tr>
              <td><span class="badge" style="background:{color}">{sev.upper()}</span></td>
              <td>{self._esc(f.get('title',''))}</td>
              <td class="mono small">{self._esc(f.get('url',''))}</td>
              <td>{self._esc(f.get('description','')[:120])}</td>
              <td class="mono small">{self._esc(f.get('cwe',''))}</td>
              <td class="tool-badge">{self._esc(f.get('tool',''))}</td>
            </tr>"""

        # URL list
        urls_html = "".join(
            f'<li class="mono small">{self._esc(u)}</li>'
            for u in crawl.get("urls", [])[:100]
        )
        if len(crawl.get("urls", [])) > 100:
            urls_html += f'<li class="more">… and {len(crawl["urls"])-100} more (see JSON)</li>'

        # Tech badges
        tech_html = "".join(
            f'<span class="tech-badge">{self._esc(t)}</span>'
            for t in recon.get("technologies", [])
        )

        # Subdomain list
        sub_html = "".join(
            f'<li class="mono small">{self._esc(s)}</li>'
            for s in recon.get("subdomains", [])
        )

        # Port table
        port_rows = ""
        for p in recon.get("open_ports", []):
            port_rows += f"""
            <tr>
              <td class="mono">{p.get('port','')}/tcp</td>
              <td>{self._esc(p.get('service',''))}</td>
              <td class="mono small">{self._esc(p.get('banner','')[:80])}</td>
            </tr>"""

        # JS files
        js_html = "".join(
            f'<li class="mono small">{self._esc(j)}</li>'
            for j in crawl.get("js_files", [])[:50]
        )

        # DNS records
        dns_html = ""
        for rtype, records in recon.get("dns", {}).items():
            for r in records:
                dns_html += f'<tr><td class="mono">{rtype}</td><td class="mono small">{self._esc(r)}</td></tr>'

        start_str = meta.get("start_time", "")
        end_str   = meta.get("end_time",   "")

        # Duration calculation
        try:
            t0 = datetime.fromisoformat(start_str)
            t1 = datetime.fromisoformat(end_str)
            duration = str(t1 - t0).split(".")[0]
        except Exception:
            duration = "N/A"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReconHawk Report – {self._esc(target['display'])}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@300;400;600;700&display=swap');
  :root {{
    --bg:       #0a0a0f;
    --surface:  #111118;
    --border:   #1e1e2a;
    --accent:   #7c3aed;
    --text:     #e4e4f0;
    --muted:    #6b6b80;
    --red:      #ff2d55;
    --orange:   #ff6b35;
    --yellow:   #ffd60a;
    --green:    #30d158;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Inter', sans-serif;
    font-size: 14px;
    line-height: 1.6;
  }}
  .mono {{ font-family: 'JetBrains Mono', monospace; }}
  .small {{ font-size: 12px; }}

  /* Header */
  header {{
    background: linear-gradient(135deg, #0f0f1a 0%, #1a0a2e 50%, #0f0f1a 100%);
    border-bottom: 1px solid var(--border);
    padding: 48px 40px 36px;
    position: relative;
    overflow: hidden;
  }}
  header::before {{
    content: '';
    position: absolute; inset: 0;
    background: radial-gradient(ellipse at 70% 50%, rgba(124,58,237,.15) 0%, transparent 60%);
    pointer-events: none;
  }}
  .header-logo {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 6px;
    text-transform: uppercase;
    color: var(--accent);
    margin-bottom: 16px;
  }}
  h1 {{
    font-size: 32px;
    font-weight: 700;
    letter-spacing: -0.5px;
    margin-bottom: 8px;
  }}
  h1 span {{ color: var(--accent); }}
  .header-meta {{
    color: var(--muted);
    font-size: 13px;
    font-family: 'JetBrains Mono', monospace;
    margin-top: 16px;
  }}

  /* Stats bar */
  .stats-bar {{
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 1px;
    background: var(--border);
    border-bottom: 1px solid var(--border);
  }}
  .stat-cell {{
    background: var(--surface);
    padding: 20px 24px;
    text-align: center;
  }}
  .stat-cell .num {{
    font-size: 28px;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
    display: block;
  }}
  .stat-cell .label {{
    font-size: 11px;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: var(--muted);
    margin-top: 4px;
  }}
  .num.critical {{ color: var(--red); }}
  .num.high     {{ color: var(--orange); }}
  .num.medium   {{ color: var(--yellow); }}
  .num.low      {{ color: var(--green); }}

  /* Layout */
  .container {{ max-width: 1400px; margin: 0 auto; padding: 0 40px 60px; }}

  /* Sections */
  section {{ margin-top: 48px; }}
  h2 {{
    font-size: 18px;
    font-weight: 600;
    letter-spacing: 0.5px;
    border-left: 3px solid var(--accent);
    padding-left: 16px;
    margin-bottom: 20px;
  }}
  h3 {{ font-size: 14px; font-weight: 600; color: var(--muted); margin: 16px 0 8px; }}

  /* Cards */
  .card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px 24px;
    margin-bottom: 16px;
  }}

  /* Tables */
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }}
  thead tr {{
    background: #16161f;
    border-bottom: 1px solid var(--border);
  }}
  th {{
    padding: 10px 14px;
    text-align: left;
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--muted);
  }}
  tbody tr {{
    border-bottom: 1px solid var(--border);
    transition: background .15s;
  }}
  tbody tr:hover {{ background: #14141c; }}
  td {{ padding: 10px 14px; vertical-align: top; }}

  /* Badges */
  .badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: 0.5px;
    color: #000;
  }}
  .tech-badge {{
    display: inline-block;
    background: #1a1a2a;
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 4px 10px;
    font-size: 12px;
    margin: 3px;
  }}
  .tool-badge {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: var(--muted);
  }}

  /* Lists */
  ul.plain {{ list-style: none; padding: 0; }}
  ul.plain li {{
    padding: 5px 0;
    border-bottom: 1px solid #16161f;
    word-break: break-all;
  }}
  ul.plain li.more {{ color: var(--muted); font-style: italic; }}

  /* Grid */
  .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }}

  /* KV pairs */
  .kv {{ display: flex; gap: 12px; padding: 8px 0; border-bottom: 1px solid #16161f; }}
  .kv .k {{ color: var(--muted); min-width: 160px; font-size: 12px; }}
  .kv .v {{ font-family: 'JetBrains Mono', monospace; font-size: 12px; word-break: break-all; }}

  footer {{
    text-align: center;
    color: var(--muted);
    font-size: 12px;
    padding: 32px 0;
    border-top: 1px solid var(--border);
    margin-top: 60px;
  }}
</style>
</head>
<body>

<header>
  <div class="header-logo">⚡ ReconHawk</div>
  <h1>Security Assessment Report — <span>{self._esc(target['display'])}</span></h1>
  <div class="header-meta">
    Scan started: {start_str} &nbsp;|&nbsp; Duration: {duration} &nbsp;|&nbsp;
    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  </div>
</header>

<!-- Stats bar -->
<div class="stats-bar">
  <div class="stat-cell">
    <span class="num critical">{counts['critical']}</span>
    <div class="label">Critical</div>
  </div>
  <div class="stat-cell">
    <span class="num high">{counts['high']}</span>
    <div class="label">High</div>
  </div>
  <div class="stat-cell">
    <span class="num medium">{counts['medium']}</span>
    <div class="label">Medium</div>
  </div>
  <div class="stat-cell">
    <span class="num low">{counts['low']}</span>
    <div class="label">Low</div>
  </div>
  <div class="stat-cell">
    <span class="num" style="color:#888">{counts['info']}</span>
    <div class="label">Info</div>
  </div>
  <div class="stat-cell">
    <span class="num" style="color:var(--accent)">{total_vulns}</span>
    <div class="label">Total</div>
  </div>
</div>

<div class="container">

  <!-- Target Info -->
  <section>
    <h2>Target Information</h2>
    <div class="card">
      <div class="kv"><span class="k">Host</span><span class="v mono">{self._esc(target['display'])}</span></div>
      <div class="kv"><span class="k">Base URL</span><span class="v mono">{self._esc(target['base_url'])}</span></div>
      <div class="kv"><span class="k">IP (Resolved)</span><span class="v mono">{self._esc(target.get('resolved_ip','N/A'))}</span></div>
      <div class="kv"><span class="k">Scheme</span><span class="v mono">{self._esc(target['scheme'])}</span></div>
      <div class="kv"><span class="k">Scan Start</span><span class="v mono">{start_str}</span></div>
      <div class="kv"><span class="k">Scan End</span><span class="v mono">{end_str}</span></div>
      <div class="kv"><span class="k">Duration</span><span class="v mono">{duration}</span></div>
    </div>
  </section>

  <!-- Technologies -->
  <section>
    <h2>Detected Technologies</h2>
    <div class="card">
      {tech_html if tech_html else '<span style="color:var(--muted)">None detected</span>'}
    </div>
  </section>

  <!-- Vulnerability Findings -->
  <section>
    <h2>Vulnerability Findings ({total_vulns})</h2>
    <div class="card" style="padding:0; overflow:hidden">
      <table>
        <thead>
          <tr>
            <th>Severity</th><th>Title</th><th>URL</th>
            <th>Description</th><th>CWE</th><th>Tool</th>
          </tr>
        </thead>
        <tbody>
          {finding_rows if finding_rows else '<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:32px">No findings recorded</td></tr>'}
        </tbody>
      </table>
    </div>
  </section>

  <div class="grid-2">

    <!-- Recon -->
    <section>
      <h2>Reconnaissance</h2>

      <h3>Subdomains ({len(recon.get('subdomains', []))})</h3>
      <div class="card">
        <ul class="plain">{sub_html or '<li style="color:var(--muted)">None found</li>'}</ul>
      </div>

      <h3>Open Ports ({len(recon.get('open_ports', []))})</h3>
      <div class="card" style="padding:0; overflow:hidden">
        <table>
          <thead><tr><th>Port</th><th>Service</th><th>Banner</th></tr></thead>
          <tbody>{port_rows or '<tr><td colspan="3" style="color:var(--muted);text-align:center;padding:16px">None found</td></tr>'}</tbody>
        </table>
      </div>

      <h3>DNS Records</h3>
      <div class="card" style="padding:0;overflow:hidden">
        <table>
          <thead><tr><th>Type</th><th>Value</th></tr></thead>
          <tbody>{dns_html or '<tr><td colspan="2" style="color:var(--muted);text-align:center;padding:16px">None</td></tr>'}</tbody>
        </table>
      </div>
    </section>

    <!-- Crawl -->
    <section>
      <h2>Crawl Results</h2>

      <h3>Discovered URLs ({len(crawl.get('urls', []))})</h3>
      <div class="card" style="max-height:300px;overflow-y:auto">
        <ul class="plain">{urls_html or '<li style="color:var(--muted)">None</li>'}</ul>
      </div>

      <h3>JavaScript Files ({len(crawl.get('js_files', []))})</h3>
      <div class="card" style="max-height:200px;overflow-y:auto">
        <ul class="plain">{js_html or '<li style="color:var(--muted)">None</li>'}</ul>
      </div>

      <h3>Parameters Discovered ({len(crawl.get('parameters', []))})</h3>
      <div class="card">
        {', '.join(f'<span class="tech-badge">{self._esc(p)}</span>'
                   for p in sorted(crawl.get('parameters', []))[:80])
         or '<span style="color:var(--muted)">None</span>'}
      </div>
    </section>

  </div>

</div>

<footer>
  Generated by <strong>ReconHawk</strong> — For authorized use only.
  Scan of <strong>{self._esc(target['display'])}</strong> completed {datetime.now().strftime('%Y-%m-%d')}.
</footer>

</body>
</html>"""

    # ── AI summary ────────────────────────────────────────────────────────────

    def _generate_ai_summary(self) -> str:
        """Call Anthropic API to generate a human-readable executive summary."""
        import os
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            Console.warning("ANTHROPIC_API_KEY not set; skipping AI summary")
            return ""

        try:
            import anthropic
        except ImportError:
            Console.warning("anthropic package not installed; skipping AI summary. "
                            "Run: pip install anthropic")
            return ""

        Console.info("Generating AI-assisted summary...")
        meta  = self.results["meta"]
        vulns = self.results.get("vulns", {})
        recon = self.results.get("recon", {})
        crawl = self.results.get("crawl", {})

        counts = {sev: len(items) for sev, items in vulns.items()
                  if isinstance(items, list)}
        all_findings = [f for items in vulns.values()
                        if isinstance(items, list) for f in items]

        findings_text = "\n".join(
            f"- [{f.get('severity','?').upper()}] {f.get('title','')}: {f.get('description','')[:120]}"
            for f in all_findings[:30]
        )

        prompt = f"""You are a cybersecurity expert reviewing automated scan results.
Write a concise executive summary (300-400 words) for the following scan:

TARGET: {meta['target']['display']}
SCAN DURATION: {meta.get('start_time','')} to {meta.get('end_time','')}

RECONNAISSANCE FINDINGS:
- Subdomains found: {len(recon.get('subdomains', []))}
- Open ports: {[p['port'] for p in recon.get('open_ports', [])]}
- Technologies: {recon.get('technologies', [])}

CRAWL STATS:
- URLs discovered: {len(crawl.get('urls', []))}
- JS files: {len(crawl.get('js_files', []))}
- Parameters: {len(crawl.get('parameters', []))}

VULNERABILITY COUNTS:
Critical: {counts.get('critical', 0)} | High: {counts.get('high', 0)} | 
Medium: {counts.get('medium', 0)} | Low: {counts.get('low', 0)} | 
Info: {counts.get('info', 0)}

TOP FINDINGS:
{findings_text}

Write a professional executive summary covering:
1. Overall risk assessment
2. Key findings and concerns
3. Top 3 recommended immediate actions
4. Overall security posture

Keep it factual, professional, and action-oriented."""

        try:
            client = anthropic.Anthropic(api_key=api_key)
            msg    = client.messages.create(
                model="claude-opus-4-5",
                max_tokens=600,
                messages=[{"role": "user", "content": prompt}],
            )
            return msg.content[0].text
        except Exception as e:
            Console.error(f"AI summary failed: {e}")
            return ""

    # ── Utility ───────────────────────────────────────────────────────────────

    @staticmethod
    def _esc(text: str) -> str:
        """HTML-escape a string."""
        return (str(text)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#x27;"))
