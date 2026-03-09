"""
AbuseIPDB API Integration
Author: Omar Tamer
"""

import requests
from typing import Dict, Any
from datetime import datetime


ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"

ABUSE_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
    4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
    7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy",
    10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking",
    16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force",
    19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
    22: "SSH", 23: "IoT Targeted"
}


class AbuseIPDBScanner:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {
            "Key": api_key,
            "Accept": "application/json"
        }

    def check_ip(self, ip: str, max_age_days: int = 90) -> Dict[str, Any]:
        try:
            response = requests.get(
                f"{ABUSEIPDB_BASE}/check",
                headers=self.headers,
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": max_age_days,
                    "verbose": True
                },
                timeout=10
            )

            if response.status_code == 200:
                return self._parse_check_result(response.json())

            return {"error": f"HTTP {response.status_code}", "ip": ip}

        except Exception as e:
            return {"error": str(e), "ip": ip}

    def check_bulk(self, ips: list) -> Dict[str, Any]:
        results = {}
        for ip in ips:
            results[ip] = self.check_ip(ip)
        return results

    def _parse_check_result(self, data: Dict) -> Dict:
        try:
            d = data.get("data", {})

            abuse_score = d.get("abuseConfidenceScore", 0)
            total_reports = d.get("totalReports", 0)
            report_categories = []

            # Parse recent reports for category info
            reports = d.get("reports", [])
            seen_categories = set()
            for report in reports[:10]:
                cats = report.get("categories", [])
                for cat_id in cats:
                    if cat_id not in seen_categories:
                        seen_categories.add(cat_id)
                        report_categories.append({
                            "id": cat_id,
                            "name": ABUSE_CATEGORIES.get(cat_id, f"Category {cat_id}")
                        })

            # Determine risk level
            if abuse_score >= 80:
                risk_level = "CRITICAL"
                risk_color = "red"
            elif abuse_score >= 50:
                risk_level = "HIGH"
                risk_color = "orange"
            elif abuse_score >= 25:
                risk_level = "MEDIUM"
                risk_color = "yellow"
            elif abuse_score > 0:
                risk_level = "LOW"
                risk_color = "yellow"
            else:
                risk_level = "CLEAN"
                risk_color = "green"

            last_reported = d.get("lastReportedAt")
            if last_reported:
                try:
                    last_dt = datetime.fromisoformat(last_reported.replace("Z", "+00:00"))
                    days_ago = (datetime.now(last_dt.tzinfo) - last_dt).days
                    last_reported_str = f"{last_reported[:10]} ({days_ago} days ago)"
                except Exception:
                    last_reported_str = last_reported
            else:
                last_reported_str = "Never"

            phishing_reports = len([
                r for r in reports
                if 7 in r.get("categories", [])  # Category 7 = Phishing
            ])

            return {
                "ip": d.get("ipAddress", ""),
                "is_public": d.get("isPublic", True),
                "abuse_confidence_score": abuse_score,
                "risk_level": risk_level,
                "total_reports": total_reports,
                "distinct_users": d.get("numDistinctUsers", 0),
                "last_reported": last_reported_str,
                "country": d.get("countryCode", "Unknown"),
                "isp": d.get("isp", "Unknown"),
                "domain": d.get("domain", ""),
                "usage_type": d.get("usageType", "Unknown"),
                "is_tor": d.get("isTor", False),
                "categories": report_categories,
                "phishing_reports": phishing_reports,
                "recent_reports": [
                    {
                        "reported_at": r.get("reportedAt", "")[:10],
                        "comment": r.get("comment", "")[:100],
                        "categories": [
                            ABUSE_CATEGORIES.get(c, str(c))
                            for c in r.get("categories", [])
                        ]
                    }
                    for r in reports[:5]
                ]
            }

        except Exception as e:
            return {"error": str(e)}
