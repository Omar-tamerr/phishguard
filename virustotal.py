"""
VirusTotal API Integration
Author: Omar Tamer
"""

import requests
import hashlib
import time
import base64
from typing import Dict, Any
from pathlib import Path


VT_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalScanner:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"x-apikey": api_key}

    def scan_url(self, url: str) -> Dict[str, Any]:
        try:
            # Submit URL
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

            # First check if already analyzed
            response = requests.get(
                f"{VT_BASE}/urls/{url_id}",
                headers=self.headers,
                timeout=10
            )

            if response.status_code == 404:
                # Submit for analysis
                submit = requests.post(
                    f"{VT_BASE}/urls",
                    headers=self.headers,
                    data={"url": url},
                    timeout=10
                )
                if submit.status_code == 200:
                    analysis_id = submit.json()["data"]["id"]
                    time.sleep(3)
                    response = requests.get(
                        f"{VT_BASE}/analyses/{analysis_id}",
                        headers=self.headers,
                        timeout=10
                    )

            if response.status_code == 200:
                return self._parse_url_result(response.json())

            return {"error": f"HTTP {response.status_code}", "malicious": 0, "total": 0}

        except Exception as e:
            return {"error": str(e), "malicious": 0, "total": 0}

    def scan_domain(self, domain: str) -> Dict[str, Any]:
        try:
            response = requests.get(
                f"{VT_BASE}/domains/{domain}",
                headers=self.headers,
                timeout=10
            )
            if response.status_code == 200:
                return self._parse_domain_result(response.json())
            return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def scan_ip(self, ip: str) -> Dict[str, Any]:
        try:
            response = requests.get(
                f"{VT_BASE}/ip_addresses/{ip}",
                headers=self.headers,
                timeout=10
            )
            if response.status_code == 200:
                return self._parse_ip_result(response.json())
            return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def scan_file(self, filepath: str) -> Dict[str, Any]:
        try:
            file_hash = self._hash_file(filepath)

            # Check if hash already known
            response = requests.get(
                f"{VT_BASE}/files/{file_hash}",
                headers=self.headers,
                timeout=10
            )

            if response.status_code == 200:
                return self._parse_file_result(response.json())

            # Upload file for analysis
            file_size = Path(filepath).stat().st_size
            if file_size > 32 * 1024 * 1024:  # 32MB limit for free API
                return {"error": "File too large for free VT API (32MB limit)"}

            with open(filepath, "rb") as f:
                upload_response = requests.post(
                    f"{VT_BASE}/files",
                    headers=self.headers,
                    files={"file": f},
                    timeout=30
                )

            if upload_response.status_code == 200:
                analysis_id = upload_response.json()["data"]["id"]
                time.sleep(5)

                result = requests.get(
                    f"{VT_BASE}/analyses/{analysis_id}",
                    headers=self.headers,
                    timeout=10
                )

                if result.status_code == 200:
                    return self._parse_analysis_result(result.json(), file_hash)

            return {"error": "Upload failed", "hash": file_hash}

        except Exception as e:
            return {"error": str(e)}

    def _hash_file(self, filepath: str) -> str:
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _parse_url_result(self, data: Dict) -> Dict:
        try:
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            results = attrs.get("last_analysis_results", {})

            malicious_engines = [
                engine for engine, result in results.items()
                if result.get("category") in ["malicious", "phishing"]
            ]

            total = sum(stats.values()) if stats else 0
            malicious = stats.get("malicious", 0) + stats.get("phishing", 0)

            return {
                "malicious": malicious,
                "suspicious": stats.get("suspicious", 0),
                "clean": stats.get("harmless", 0) + stats.get("undetected", 0),
                "total": total,
                "detection_rate": f"{malicious}/{total}" if total else "0/0",
                "flagged_by": malicious_engines[:10],
                "categories": attrs.get("categories", {}),
                "reputation": attrs.get("reputation", 0),
                "threat_names": list(set([
                    r.get("result") for r in results.values()
                    if r.get("result") and r.get("category") == "malicious"
                ]))[:5]
            }
        except Exception as e:
            return {"error": str(e)}

    def _parse_domain_result(self, data: Dict) -> Dict:
        try:
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            total = sum(stats.values()) if stats else 0
            malicious = stats.get("malicious", 0)

            return {
                "malicious": malicious,
                "total": total,
                "detection_rate": f"{malicious}/{total}" if total else "0/0",
                "reputation": attrs.get("reputation", 0),
                "categories": attrs.get("categories", {}),
                "creation_date": attrs.get("creation_date", "Unknown"),
                "registrar": attrs.get("registrar", "Unknown"),
                "country": attrs.get("country", "Unknown")
            }
        except Exception as e:
            return {"error": str(e)}

    def _parse_ip_result(self, data: Dict) -> Dict:
        try:
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            total = sum(stats.values()) if stats else 0
            malicious = stats.get("malicious", 0)

            return {
                "malicious": malicious,
                "total": total,
                "detection_rate": f"{malicious}/{total}" if total else "0/0",
                "reputation": attrs.get("reputation", 0),
                "country": attrs.get("country", "Unknown"),
                "asn": attrs.get("asn", "Unknown"),
                "as_owner": attrs.get("as_owner", "Unknown"),
                "network": attrs.get("network", "Unknown")
            }
        except Exception as e:
            return {"error": str(e)}

    def _parse_file_result(self, data: Dict) -> Dict:
        try:
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            total = sum(stats.values()) if stats else 0
            malicious = stats.get("malicious", 0)

            return {
                "malicious": malicious,
                "total": total,
                "detection_rate": f"{malicious}/{total}" if total else "0/0",
                "sha256": attrs.get("sha256", ""),
                "md5": attrs.get("md5", ""),
                "file_type": attrs.get("type_description", "Unknown"),
                "size": attrs.get("size", 0),
                "threat_names": attrs.get("popular_threat_name", ""),
                "tags": attrs.get("tags", [])
            }
        except Exception as e:
            return {"error": str(e)}

    def _parse_analysis_result(self, data: Dict, file_hash: str) -> Dict:
        try:
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("stats", {})
            results = attrs.get("results", {})

            total = sum(stats.values()) if stats else 0
            malicious = stats.get("malicious", 0)

            malicious_engines = [
                engine for engine, result in results.items()
                if result.get("category") in ["malicious"]
            ]

            return {
                "malicious": malicious,
                "suspicious": stats.get("suspicious", 0),
                "clean": stats.get("harmless", 0) + stats.get("undetected", 0),
                "total": total,
                "detection_rate": f"{malicious}/{total}" if total else "0/0",
                "sha256": file_hash,
                "flagged_by": malicious_engines[:10],
                "status": attrs.get("status", "completed")
            }
        except Exception as e:
            return {"error": str(e)}
