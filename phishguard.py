#!/usr/bin/env python3
"""
PhishGuard AI - Advanced Phishing Detection Tool
Author: Omar Tamer
"""

import argparse
import sys
import os
import json
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.columns import Columns
from rich.align import Align
import time

console = Console()

BANNER = """
[bold red]
██████╗ ██╗  ██╗██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██████╔╝███████║██║███████╗███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
██║     ██║  ██║██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ [/bold red]
[bold cyan]
 █████╗ ██╗
██╔══██╗██║
███████║██║
██╔══██║██║
██║  ██║██║
╚═╝  ╚═╝╚═╝[/bold cyan]
"""

def print_banner():
    console.print(BANNER)
    console.print(Panel.fit(
        "[bold white]🛡️  Advanced AI/ML Phishing Detection & Threat Intelligence Platform[/bold white]\n"
        "[dim]Powered by VirusTotal • AbuseIPDB • ML Classifier • AI Text Detection[/dim]\n"
        "[bold yellow]                    Made with ❤️  by Omar Tamer[/bold yellow]",
        border_style="red",
        padding=(1, 4)
    ))
    console.print()

def print_scan_header(target: str, scan_type: str):
    console.print(Panel(
        f"[bold white]🎯 Target:[/bold white] [cyan]{target}[/cyan]\n"
        f"[bold white]📋 Scan Type:[/bold white] [yellow]{scan_type}[/yellow]\n"
        f"[bold white]🕐 Started:[/bold white] [dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]",
        title="[bold red][ SCAN INITIATED ][/bold red]",
        border_style="yellow",
        padding=(0, 2)
    ))
    console.print()

def animated_scan(label: str, steps: list):
    with Progress(
        SpinnerColumn(spinner_name="dots", style="bold red"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=40, style="red", complete_style="green"),
        TextColumn("[bold white]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        task = progress.add_task(f"[cyan]{label}", total=len(steps))
        for step in steps:
            progress.update(task, description=f"[cyan]{step}")
            time.sleep(0.4)
            progress.advance(task)
    console.print()

def run_full_scan(args, config):
    from core.email_analyzer import EmailAnalyzer
    from core.url_analyzer import URLAnalyzer
    from core.domain_reputation import DomainReputation
    from core.virustotal import VirusTotalScanner
    from core.abuseipdb import AbuseIPDBScanner
    from core.ai_text_detector import AITextDetector
    from core.screenshot_analyzer import ScreenshotAnalyzer
    from ml.url_classifier import URLClassifier
    from utils.report import ReportGenerator

    results = {
        "scan_date": datetime.now().isoformat(),
        "target": {},
        "email": {},
        "urls": [],
        "domain": {},
        "virustotal": {},
        "abuseipdb": {},
        "ai_detection": {},
        "ml_classifier": {},
        "risk_score": 0,
        "verdict": ""
    }

    vt_key = args.vt_key or config.get("vt_key")
    abuse_key = args.abuse_key or config.get("abuse_key")

    # ── EMAIL SCAN ──────────────────────────────────────────────────────────
    if args.email:
        print_scan_header(args.email, "Full Email Analysis")
        animated_scan("Analyzing Email...", [
            "Parsing headers", "Checking SPF/DKIM/DMARC",
            "Extracting URLs", "Scanning body content",
            "Running AI detection"
        ])

        analyzer = EmailAnalyzer(args.email)
        email_results = analyzer.analyze()
        results["email"] = email_results

        # AI Text Detection on body
        ai_detector = AITextDetector()
        ai_results = ai_detector.analyze(email_results.get("body", ""))
        results["ai_detection"] = ai_results

        # URL Analysis + ML
        url_classifier = URLClassifier()
        for url in email_results.get("urls", []):
            animated_scan(f"Scanning URL: {url[:50]}...", [
                "Pattern analysis", "ML classification",
                "Domain reputation", "Blacklist check"
            ])
            url_result = URLAnalyzer(url).analyze()
            url_result["ml"] = url_classifier.classify(url)

            if vt_key:
                animated_scan("VirusTotal Scan...", ["Uploading to VT", "Waiting for results", "Parsing 70+ engines"])
                vt = VirusTotalScanner(vt_key)
                url_result["virustotal"] = vt.scan_url(url)

            results["urls"].append(url_result)

        # Domain Reputation
        domain = email_results.get("sender_domain", "")
        if domain:
            animated_scan(f"Domain Reputation: {domain}", [
                "WHOIS lookup", "DNS records", "Blacklist check", "Lookalike scoring"
            ])
            results["domain"] = DomainReputation(domain).analyze()

            # AbuseIPDB on resolved IPs
            if abuse_key:
                ip = results["domain"].get("ip")
                if ip:
                    animated_scan(f"AbuseIPDB: {ip}", ["Querying AbuseIPDB", "Parsing reports"])
                    results["abuseipdb"] = AbuseIPDBScanner(abuse_key).check_ip(ip)

        # Screenshot
        if args.screenshot:
            for url in email_results.get("urls", [])[:2]:
                animated_scan(f"Screenshot: {url[:50]}", ["Launching browser", "Capturing page", "Analyzing visual"])
                shot = ScreenshotAnalyzer()
                results["screenshot"] = shot.capture(url)

    # ── URL ONLY SCAN ───────────────────────────────────────────────────────
    elif args.url:
        print_scan_header(args.url, "URL Scan")
        animated_scan("Deep URL Analysis...", [
            "Parsing structure", "ML classification",
            "Domain WHOIS", "Blacklist check", "VT scan"
        ])

        url_classifier = URLClassifier()
        url_result = URLAnalyzer(args.url).analyze()
        url_result["ml"] = url_classifier.classify(args.url)
        results["urls"] = [url_result]

        domain = url_result.get("domain", "")
        if domain:
            results["domain"] = DomainReputation(domain).analyze()

        if vt_key:
            vt = VirusTotalScanner(vt_key)
            results["virustotal"] = vt.scan_url(args.url)
            results["virustotal"]["domain"] = vt.scan_domain(domain) if domain else {}

    # ── FILE SCAN ───────────────────────────────────────────────────────────
    elif args.file:
        print_scan_header(args.file, "File/Attachment Scan")
        animated_scan("File Analysis...", [
            "Hashing file", "Checking VT database",
            "Uploading sample", "Waiting for analysis", "Parsing results"
        ])

        if vt_key:
            vt = VirusTotalScanner(vt_key)
            results["virustotal"] = vt.scan_file(args.file)
        else:
            console.print("[yellow]⚠️  No VirusTotal API key — skipping file scan[/yellow]")

    # ── DOMAIN ONLY ─────────────────────────────────────────────────────────
    elif args.domain:
        print_scan_header(args.domain, "Domain Intelligence")
        animated_scan("Domain Deep Scan...", [
            "WHOIS lookup", "DNS enumeration", "Blacklist check",
            "Lookalike detection", "IP reputation"
        ])

        results["domain"] = DomainReputation(args.domain).analyze()
        ip = results["domain"].get("ip")

        if vt_key:
            vt = VirusTotalScanner(vt_key)
            results["virustotal"]["domain"] = vt.scan_domain(args.domain)
            if ip:
                results["virustotal"]["ip"] = vt.scan_ip(ip)

        if abuse_key and ip:
            results["abuseipdb"] = AbuseIPDBScanner(abuse_key).check_ip(ip)

    # ── GENERATE REPORT ─────────────────────────────────────────────────────
    reporter = ReportGenerator(results)
    reporter.print_rich_report()

    if args.report:
        reporter.export_json(args.report)
        console.print(f"\n[bold green]📄 JSON report saved → [cyan]{args.report}[/cyan][/bold green]")

def load_config():
    config_path = os.path.expanduser("~/.phishguard/config.json")
    if os.path.exists(config_path):
        with open(config_path) as f:
            return json.load(f)
    return {}

def save_config(vt_key=None, abuse_key=None):
    config_dir = os.path.expanduser("~/.phishguard")
    os.makedirs(config_dir, exist_ok=True)
    config = load_config()
    if vt_key:
        config["vt_key"] = vt_key
    if abuse_key:
        config["abuse_key"] = abuse_key
    with open(os.path.join(config_dir, "config.json"), "w") as f:
        json.dump(config, f, indent=2)
    console.print("[bold green]✅ API keys saved to ~/.phishguard/config.json[/bold green]")

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="PhishGuard AI — Advanced Phishing Detection Tool by Omar Tamer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  phishguard --email suspicious.eml --screenshot --report out.json
  phishguard --url "http://paypa1.com/login" --vt-key YOUR_KEY
  phishguard --file attachment.pdf --vt-key YOUR_KEY
  phishguard --domain "paypa1-verify.com" --abuse-key YOUR_KEY
  phishguard --config --vt-key YOUR_KEY --abuse-key YOUR_KEY
        """
    )

    # Scan targets
    targets = parser.add_argument_group("🎯 Scan Targets")
    targets.add_argument("--email", metavar="FILE", help="Analyze .eml email file")
    targets.add_argument("--url", metavar="URL", help="Scan a URL")
    targets.add_argument("--file", metavar="FILE", help="Scan file/attachment via VirusTotal")
    targets.add_argument("--domain", metavar="DOMAIN", help="Analyze a domain")

    # API Keys
    api = parser.add_argument_group("🔑 API Keys")
    api.add_argument("--vt-key", metavar="KEY", help="VirusTotal API key")
    api.add_argument("--abuse-key", metavar="KEY", help="AbuseIPDB API key")

    # Options
    opts = parser.add_argument_group("⚙️  Options")
    opts.add_argument("--screenshot", action="store_true", help="Capture website screenshots")
    opts.add_argument("--report", metavar="FILE", help="Export JSON report to file")
    opts.add_argument("--config", action="store_true", help="Save API keys to config")
    opts.add_argument("--train", action="store_true", help="Retrain ML URL classifier")

    args = parser.parse_args()

    config = load_config()

    if args.config:
        save_config(args.vt_key, args.abuse_key)
        return

    if args.train:
        from ml.train import train_model
        console.print("[bold yellow]🤖 Training ML URL Classifier...[/bold yellow]")
        train_model()
        return

    if not any([args.email, args.url, args.file, args.domain]):
        parser.print_help()
        console.print("\n[bold red]❌ Please specify a scan target.[/bold red]")
        sys.exit(1)

    try:
        run_full_scan(args, config)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]⚠️  Scan interrupted by user[/bold yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]❌ Error: {e}[/bold red]")
        if os.environ.get("PHISHGUARD_DEBUG"):
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
