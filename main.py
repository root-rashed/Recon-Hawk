#!/usr/bin/env python3
"""
ReconHawk - Automated Reconnaissance & Vulnerability Scanner
A modular, CLI-based security assessment tool for authorized targets.
"""

import argparse
import sys
import time
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from modules.recon import ReconModule
from modules.crawler import CrawlerModule
from modules.vuln_scanner import VulnScannerModule
from modules.report_generator import ReportGenerator
from utils.console import Console
from utils.validator import validate_target


BANNER = r"""
╦═╗╔═╗╔═╗╔═╗╔╗╔╦ ╦╔═╗╦ ╦╦╔═
╠╦╝║╣ ║  ║ ║║║║╠═╣╠═╣║║║╠╩╗
╩╚═╚═╝╚═╝╚═╝╝╚╝╩ ╩╩ ╩╩╚╝╩ ╩
  Automated Reconnaissance & Vulnerability Scanner
  [!] For authorized targets only | v1.0.0
"""


def parse_args():
    parser = argparse.ArgumentParser(
        prog="reconhawk",
        description="ReconHawk - Automated Reconnaissance & Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -t example.com
  python main.py -t 192.168.1.1 --ports 1-1000
  python main.py -t https://example.com --skip-vuln
  python main.py -t example.com --output-dir ./my_reports --threads 10
  python main.py -t example.com --html --ai-summary
        """
    )

    # Target
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target domain, subdomain, URL, or IP address"
    )

    # Scan options
    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument(
        "--ports",
        default="21,22,23,25,53,80,110,143,443,445,3306,3389,8080,8443,8888",
        help="Comma-separated ports or range (default: common web ports)"
    )
    scan_group.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Number of concurrent threads (default: 10)"
    )
    scan_group.add_argument(
        "--depth",
        type=int,
        default=2,
        help="Crawling depth (default: 2)"
    )
    scan_group.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    scan_group.add_argument(
        "--rate-limit",
        type=float,
        default=0.1,
        help="Delay between requests in seconds (default: 0.1)"
    )
    scan_group.add_argument(
        "--user-agent",
        default="Mozilla/5.0 (compatible; ReconHawk/1.0; +https://github.com/reconhawk)",
        help="Custom User-Agent string"
    )

    # Module toggles
    module_group = parser.add_argument_group("Module Toggles")
    module_group.add_argument("--skip-recon", action="store_true", help="Skip reconnaissance phase")
    module_group.add_argument("--skip-crawl", action="store_true", help="Skip crawling phase")
    module_group.add_argument("--skip-vuln", action="store_true", help="Skip vulnerability scanning phase")
    module_group.add_argument("--skip-nikto", action="store_true", help="Skip Nikto scan")
    module_group.add_argument("--skip-nuclei", action="store_true", help="Skip Nuclei scan")

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "--output-dir",
        default="./reports",
        help="Output directory for reports (default: ./reports)"
    )
    output_group.add_argument("--html", action="store_true", help="Generate HTML report (bonus feature)")
    output_group.add_argument("--ai-summary", action="store_true", help="Generate AI-assisted summary (bonus feature)")
    output_group.add_argument("--quiet", "-q", action="store_true", help="Suppress banner and verbose output")
    output_group.add_argument("--no-color", action="store_true", help="Disable colored output")

    return parser.parse_args()


def run_phase(name, func, *args, **kwargs):
    """Run a scan phase with timing and error handling."""
    Console.section(f"Phase: {name}")
    start = time.time()
    try:
        result = func(*args, **kwargs)
        elapsed = time.time() - start
        Console.success(f"{name} completed in {elapsed:.1f}s")
        return result
    except KeyboardInterrupt:
        Console.warning(f"{name} interrupted by user")
        return None
    except Exception as e:
        Console.error(f"{name} failed: {e}")
        return None


def main():
    args = parse_args()

    # Configure console
    Console.configure(no_color=args.no_color, quiet=args.quiet)

    if not args.quiet:
        Console.print_raw(BANNER, color="cyan")

    # Validate target
    Console.info(f"Validating target: {args.target}")
    target_info = validate_target(args.target)
    if not target_info:
        Console.error("Invalid target. Please provide a valid domain, subdomain, URL, or IP address.")
        sys.exit(1)

    Console.success(f"Target validated: {target_info['display']}")
    Console.info(f"Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    Console.info(f"Threads: {args.threads} | Depth: {args.depth} | Timeout: {args.timeout}s")

    # Initialize results container
    scan_results = {
        "meta": {
            "target": target_info,
            "args": vars(args),
            "start_time": datetime.now().isoformat(),
            "end_time": None,
        },
        "recon": {},
        "crawl": {},
        "vulns": {},
    }

    # ── Phase 1: Reconnaissance ──────────────────────────────────────────────
    if not args.skip_recon:
        recon = ReconModule(
            target=target_info,
            timeout=args.timeout,
            threads=args.threads,
            ports=args.ports,
            user_agent=args.user_agent,
            rate_limit=args.rate_limit,
        )
        recon_data = run_phase("Reconnaissance", recon.run)
        if recon_data:
            scan_results["recon"] = recon_data
    else:
        Console.warning("Reconnaissance phase skipped")

    # ── Phase 2: Crawling ────────────────────────────────────────────────────
    if not args.skip_crawl:
        crawler = CrawlerModule(
            target=target_info,
            depth=args.depth,
            threads=args.threads,
            timeout=args.timeout,
            user_agent=args.user_agent,
            rate_limit=args.rate_limit,
        )
        crawl_data = run_phase("Web Crawling", crawler.run)
        if crawl_data:
            scan_results["crawl"] = crawl_data
    else:
        Console.warning("Crawling phase skipped")

    # ── Phase 3: Vulnerability Scanning ──────────────────────────────────────
    if not args.skip_vuln:
        vuln_scanner = VulnScannerModule(
            target=target_info,
            timeout=args.timeout,
            threads=args.threads,
            skip_nikto=args.skip_nikto,
            skip_nuclei=args.skip_nuclei,
            rate_limit=args.rate_limit,
        )
        vuln_data = run_phase("Vulnerability Scanning", vuln_scanner.run)
        if vuln_data:
            scan_results["vulns"] = vuln_data
    else:
        Console.warning("Vulnerability scanning phase skipped")

    # ── Phase 4: Report Generation ───────────────────────────────────────────
    scan_results["meta"]["end_time"] = datetime.now().isoformat()
    os.makedirs(args.output_dir, exist_ok=True)

    reporter = ReportGenerator(
        results=scan_results,
        output_dir=args.output_dir,
        generate_html=args.html,
        ai_summary=args.ai_summary,
    )

    Console.section("Phase: Report Generation")
    report_paths = reporter.generate()

    Console.section("Scan Complete")
    Console.success(f"JSON Report : {report_paths.get('json', 'N/A')}")
    if args.html and report_paths.get("html"):
        Console.success(f"HTML Report : {report_paths['html']}")

    # Print summary stats
    total_vulns = 0
    if scan_results["vulns"]:
        for findings in scan_results["vulns"].values():
            if isinstance(findings, list):
                total_vulns += len(findings)

    Console.print_raw("\n┌─ Summary " + "─" * 50)
    Console.print_raw(f"│  URLs Discovered    : {len(scan_results['crawl'].get('urls', []))}")
    Console.print_raw(f"│  JS Files Found     : {len(scan_results['crawl'].get('js_files', []))}")
    Console.print_raw(f"│  Parameters Found   : {len(scan_results['crawl'].get('parameters', []))}")
    Console.print_raw(f"│  Subdomains Found   : {len(scan_results['recon'].get('subdomains', []))}")
    Console.print_raw(f"│  Open Ports         : {len(scan_results['recon'].get('open_ports', []))}")
    Console.print_raw(f"│  Vulnerabilities    : {total_vulns}")
    Console.print_raw("└" + "─" * 60 + "\n")


if __name__ == "__main__":
    main()
