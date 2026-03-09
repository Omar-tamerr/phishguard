"""
Rich CLI Report Generator
Author: Omar Tamer
"""

import json
from typing import Dict, Any
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.rule import Rule
from rich.columns import Columns

console = Console()


def risk_color(score: int) -> str:
    if score >= 75:
        return "bold red"
    elif score >= 50:
        return "bold yellow"
    elif score >= 25:
        return "yellow"
    return "bold green"


def verdict_icon(score: int) -> str:
    if score >= 75:
        return "🔴"
    elif score >= 50:
        return "🟠"
    elif score >= 25:
        return "🟡"
    return "🟢"


class ReportGenerator:
    def __init__(self, results: Dict[str, Any]):
        self.results = results
        self.overall_score = self._calculate_overall_score()

    def _calculate_overall_score(self) -> int:
        scores = []

        email = self.results.get("email", {})
        if email:
            risk = email.get("risk_indicators", {}).get("score", 0)
            scores.append(risk)

            # SPF/DKIM/DMARC failures
            spf = email.get("spf", {}).get("result", "")
            dkim = email.get("dkim", {}).get("result", "")
            dmarc = email.get("dmarc", {}).get("result", "")
            auth_failures = sum([
                spf in ["fail", "softfail"],
                dkim in ["missing", "malformed"],
                dmarc in ["missing", "fail"]
            ])
            scores.append(auth_failures * 15)

        for url_data in self.results.get("urls", []):
            ml = url_data.get("ml", {})
            if ml.get("verdict") == "MALICIOUS":
                scores.append(ml.get("malicious_probability", 70))

        domain = self.results.get("domain", {})
        if domain:
            scores.append(domain.get("risk_score", 0))

        vt = self.results.get("virustotal", {})
        if vt and not vt.get("error"):
            malicious = vt.get("malicious", 0)
            total = vt.get("total", 1)
            if total > 0:
                scores.append(min(int((malicious / total) * 100 * 1.5), 100))

        abuse = self.results.get("abuseipdb", {})
        if abuse and not abuse.get("error"):
            scores.append(abuse.get("abuse_confidence_score", 0))

        ai = self.results.get("ai_detection", {})
        if ai:
            scores.append(int(ai.get("ai_score", 0) * 0.4))  # AI detection contributes 40%

        return min(int(sum(scores) / max(len(scores), 1)), 100) if scores else 0

    def print_rich_report(self):
        self._print_email_section()
        self._print_ai_detection_section()
        self._print_url_section()
        self._print_domain_section()
        self._print_virustotal_section()
        self._print_abuseipdb_section()
        self._print_final_verdict()

    def _print_email_section(self):
        email = self.results.get("email", {})
        if not email:
            return

        console.print(Rule("[bold cyan]📧 EMAIL ANALYSIS[/bold cyan]"))

        headers = email.get("headers", {})
        spf = email.get("spf", {})
        dkim = email.get("dkim", {})
        dmarc = email.get("dmarc", {})
        spoofing = email.get("spoofing", {})

        # Header table
        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        t.add_column("Field", style="bold white", width=20)
        t.add_column("Value")

        t.add_row("From", headers.get("from", "N/A"))
        t.add_row("Reply-To", headers.get("reply_to", "N/A"))
        t.add_row("Subject", headers.get("subject", "N/A"))
        t.add_row("Date", headers.get("date", "N/A"))

        spf_icon = "❌" if spf.get("result") in ["fail", "softfail"] else "✅" if spf.get("result") == "pass" else "⚠️"
        dkim_icon = "❌" if dkim.get("result") in ["missing", "malformed"] else "✅"
        dmarc_icon = "❌" if dmarc.get("result") in ["missing", "fail"] else "✅"

        t.add_row("SPF", f"{spf_icon} {spf.get('result', 'unknown').upper()}")
        t.add_row("DKIM", f"{dkim_icon} {dkim.get('result', 'unknown').upper()}")
        t.add_row("DMARC", f"{dmarc_icon} {dmarc.get('result', 'unknown').upper()} (policy: {dmarc.get('policy', 'none')})")

        if email.get("reply_to_mismatch"):
            t.add_row("Reply-To Mismatch", "[bold red]⚠️  DETECTED — Reply-To domain differs from sender[/bold red]")

        console.print(t)

        # Spoofing
        if spoofing.get("detected"):
            for indicator in spoofing.get("indicators", []):
                console.print(f"  [bold red]🚨 SPOOFING: {indicator}[/bold red]")

        # Urgency keywords
        urgency = email.get("urgency_keywords", [])
        if urgency:
            console.print(f"\n  [yellow]⚠️  Urgency keywords: [/yellow][dim]{', '.join(urgency[:8])}[/dim]")

        # Attachments
        attachments = email.get("attachments", [])
        dangerous = [a for a in attachments if a.get("dangerous")]
        if dangerous:
            for att in dangerous:
                console.print(f"  [bold red]📎 DANGEROUS ATTACHMENT: {att['filename']} ({att['extension']})[/bold red]")

        console.print()

    def _print_ai_detection_section(self):
        ai = self.results.get("ai_detection", {})
        if not ai or ai.get("verdict") == "INSUFFICIENT_TEXT":
            return

        console.print(Rule("[bold cyan]🤖 AI TEXT DETECTION[/bold cyan]"))

        score = ai.get("ai_score", 0)
        verdict = ai.get("verdict", "")
        color = risk_color(score)

        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        t.add_column("Metric", style="bold white", width=25)
        t.add_column("Value")

        t.add_row("AI Score", f"[{color}]{score}% — {verdict}[/{color}]")
        t.add_row("Confidence", ai.get("confidence", ""))

        signals = ai.get("signals", {})
        t.add_row("Burstiness", f"{signals.get('burstiness', 0):.3f} {'(low=AI-like)' if signals.get('burstiness', 1) < 0.4 else '(normal)'}")
        t.add_row("Perplexity", f"{signals.get('perplexity', 0):.3f} {'(low=AI-like)' if signals.get('perplexity', 1) < 0.4 else '(normal)'}")
        t.add_row("AI Phrase Ratio", f"{signals.get('ai_phrases', 0):.3f}")
        t.add_row("Formality Score", f"{signals.get('formality_score', 0):.3f}")

        phrases = ai.get("ai_phrases_found", [])
        if phrases:
            t.add_row("AI Phrases Found", f"[yellow]{', '.join(phrases[:5])}[/yellow]")

        console.print(t)
        if ai.get("explanation"):
            console.print(f"  [dim]→ {ai['explanation']}[/dim]")
        console.print()

    def _print_url_section(self):
        urls = self.results.get("urls", [])
        if not urls:
            return

        console.print(Rule("[bold cyan]🔗 URL ANALYSIS[/bold cyan]"))

        for i, url_data in enumerate(urls, 1):
            ml = url_data.get("ml", {})
            verdict = ml.get("verdict", "UNKNOWN")
            confidence = ml.get("confidence", 0)

            verdict_color = "red" if verdict == "MALICIOUS" else "yellow" if verdict == "SUSPICIOUS" else "green"
            icon = "🔴" if verdict == "MALICIOUS" else "🟡" if verdict == "SUSPICIOUS" else "🟢"

            console.print(f"  [{i}] [cyan]{url_data.get('url', '')[:70]}[/cyan]")

            t = Table(box=box.SIMPLE, show_header=False, padding=(0, 4))
            t.add_column("Key", width=25)
            t.add_column("Value")

            t.add_row("ML Verdict", f"[{verdict_color}]{icon} {verdict} ({confidence}% confidence)[/{verdict_color}]")

            typo = url_data.get("typosquatting", {})
            if typo.get("detected"):
                for m in typo.get("matches", []):
                    t.add_row("Typosquatting", f"[red]⚠️  Mimics '{m['brand']}' ({int(m['similarity']*100)}% similar) via {m['technique']}[/red]")

            sub = url_data.get("subdomain_abuse", {})
            if sub.get("detected"):
                t.add_row("Subdomain Abuse", f"[red]{sub['technique']}[/red]")

            if url_data.get("is_url_shortener", {}).get("detected"):
                svc = url_data.get("is_url_shortener", {}).get("service", "")
                t.add_row("URL Shortener", f"[yellow]⚠️  {svc}[/yellow]")
                redirects = url_data.get("redirect_chain", [])
                if redirects:
                    t.add_row("Redirects To", f"[yellow]{redirects[-1][:60]}[/yellow]")

            if url_data.get("ip_in_url"):
                t.add_row("IP in URL", "[red]⚠️  Direct IP address used instead of domain[/red]")

            if not url_data.get("is_https"):
                t.add_row("HTTPS", "[red]❌ No HTTPS[/red]")

            keywords = url_data.get("suspicious_keywords", [])
            if keywords:
                t.add_row("Sus. Keywords", f"[yellow]{', '.join(keywords)}[/yellow]")

            # VT results for this URL
            vt = url_data.get("virustotal", {})
            if vt and not vt.get("error"):
                mal = vt.get("malicious", 0)
                total = vt.get("total", 0)
                vt_color = "red" if mal > 5 else "yellow" if mal > 0 else "green"
                t.add_row("VirusTotal", f"[{vt_color}]{mal}/{total} engines flagged[/{vt_color}]")
                if vt.get("threat_names"):
                    t.add_row("Threat Names", f"[red]{', '.join(vt['threat_names'][:3])}[/red]")

            console.print(t)
            console.print()

    def _print_domain_section(self):
        domain = self.results.get("domain", {})
        if not domain:
            return

        console.print(Rule("[bold cyan]🌐 DOMAIN INTELLIGENCE[/bold cyan]"))

        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        t.add_column("Field", style="bold white", width=22)
        t.add_column("Value")

        whois = domain.get("whois", {})
        age = whois.get("age_days")
        age_str = f"{age} days" if age is not None else "Unknown"
        age_color = "red" if age and age < 30 else "yellow" if age and age < 90 else "green"

        t.add_row("Domain", domain.get("domain", ""))
        t.add_row("IP Address", domain.get("ip", "N/A"))
        t.add_row("Registrar", whois.get("registrar", "Unknown"))
        t.add_row("Age", f"[{age_color}]{age_str}[/{age_color}]")
        t.add_row("Country", whois.get("country", "Unknown"))

        bl = domain.get("blacklists", {})
        bl_color = "red" if bl.get("listed") else "green"
        bl_str = f"LISTED ({', '.join(bl.get('lists', []))})" if bl.get("listed") else "CLEAN"
        t.add_row("Blacklists", f"[{bl_color}]{bl_str}[/{bl_color}]")

        la = domain.get("lookalike", {})
        if la.get("detected"):
            t.add_row("Lookalike", f"[red]⚠️  {la['similarity_score']}% similar to {la['target_brand']}[/red]")

        ssl = domain.get("ssl", {})
        if ssl.get("valid"):
            ssl_str = f"✅ Valid — issued by {ssl.get('issued_by', 'Unknown')} ({ssl.get('days_remaining', 0)} days left)"
            if ssl.get("self_signed"):
                ssl_str = f"⚠️  Self-signed certificate"
            t.add_row("SSL", ssl_str)
        else:
            t.add_row("SSL", f"[red]❌ {ssl.get('error', 'Invalid')}[/red]")

        console.print(t)
        console.print()

    def _print_virustotal_section(self):
        vt = self.results.get("virustotal", {})
        if not vt or (not vt.get("malicious") and not vt.get("total")):
            return

        console.print(Rule("[bold cyan]🔍 VIRUSTOTAL RESULTS[/bold cyan]"))

        mal = vt.get("malicious", 0)
        total = vt.get("total", 0)
        color = "red" if mal > 5 else "yellow" if mal > 0 else "green"

        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        t.add_column("Metric", style="bold white", width=22)
        t.add_column("Value")

        t.add_row("Detection Rate", f"[{color}]{vt.get('detection_rate', '0/0')}[/{color}]")
        t.add_row("Malicious", f"[red]{mal}[/red]")
        t.add_row("Suspicious", str(vt.get("suspicious", 0)))
        t.add_row("Clean", str(vt.get("clean", 0)))

        if vt.get("flagged_by"):
            t.add_row("Flagged By", f"[red]{', '.join(vt['flagged_by'][:5])}[/red]")

        if vt.get("threat_names"):
            t.add_row("Threat Names", f"[red]{', '.join(vt['threat_names'][:3])}[/red]")

        # File-specific fields
        if vt.get("sha256"):
            t.add_row("SHA256", f"[dim]{vt['sha256'][:32]}...[/dim]")
            t.add_row("File Type", vt.get("file_type", "Unknown"))

        console.print(t)
        console.print()

    def _print_abuseipdb_section(self):
        abuse = self.results.get("abuseipdb", {})
        if not abuse or abuse.get("error"):
            return

        console.print(Rule("[bold cyan]🚨 ABUSEIPDB RESULTS[/bold cyan]"))

        score = abuse.get("abuse_confidence_score", 0)
        risk = abuse.get("risk_level", "UNKNOWN")
        color = risk_color(score)

        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        t.add_column("Metric", style="bold white", width=22)
        t.add_column("Value")

        t.add_row("IP", abuse.get("ip", ""))
        t.add_row("Abuse Score", f"[{color}]{score}% — {risk}[/{color}]")
        t.add_row("Total Reports", str(abuse.get("total_reports", 0)))
        t.add_row("Distinct Users", str(abuse.get("distinct_users", 0)))
        t.add_row("Last Reported", abuse.get("last_reported", "Never"))
        t.add_row("Country", abuse.get("country", "Unknown"))
        t.add_row("ISP", abuse.get("isp", "Unknown"))
        t.add_row("Usage Type", abuse.get("usage_type", "Unknown"))

        if abuse.get("is_tor"):
            t.add_row("TOR Node", "[bold red]⚠️  Known TOR exit node[/bold red]")

        if abuse.get("phishing_reports", 0) > 0:
            t.add_row("Phishing Reports", f"[red]{abuse['phishing_reports']} phishing reports[/red]")

        cats = abuse.get("categories", [])
        if cats:
            cat_names = [c["name"] for c in cats[:5]]
            t.add_row("Attack Types", f"[yellow]{', '.join(cat_names)}[/yellow]")

        console.print(t)
        console.print()

    def _print_final_verdict(self):
        score = self.overall_score
        color = risk_color(score)
        icon = verdict_icon(score)

        if score >= 75:
            verdict = "PHISHING CONFIRMED"
            actions = [
                "Block domain at firewall/DNS immediately",
                "Report to PhishTank & Google Safe Browsing",
                "Alert all employees — active campaign",
                "Forward to IR team for full investigation",
                "Reset credentials of any affected users"
            ]
        elif score >= 50:
            verdict = "HIGHLY SUSPICIOUS"
            actions = [
                "Do NOT click any links in this email",
                "Quarantine email from mailbox",
                "Report domain to abuse registrar",
                "Monitor network for connection attempts"
            ]
        elif score >= 25:
            verdict = "SUSPICIOUS — FURTHER REVIEW NEEDED"
            actions = [
                "Treat with caution",
                "Verify sender through alternative channel",
                "Do not provide credentials"
            ]
        else:
            verdict = "LIKELY LEGITIMATE"
            actions = ["No immediate action required"]

        console.print()
        console.print(Panel(
            f"[{color}]{icon}  RISK SCORE: {score} / 100[/{color}]\n"
            f"[bold white]VERDICT: {verdict}[/bold white]\n\n"
            "[bold yellow]RECOMMENDED ACTIONS:[/bold yellow]\n" +
            "\n".join(f"  [dim]├─[/dim] {a}" for a in actions),
            title="[bold red][ FINAL VERDICT ][/bold red]",
            border_style="red" if score >= 75 else "yellow" if score >= 25 else "green",
            padding=(1, 4)
        ))

        console.print(f"\n[dim]  PhishGuard AI • Made with ❤️  by Omar Tamer • Scan: {self.results.get('scan_date', '')[:19]}[/dim]\n")

    def export_json(self, filepath: str):
        with open(filepath, "w") as f:
            json.dump(self.results, f, indent=2, default=str)
