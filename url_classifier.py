"""
ML-based URL Classifier
Uses Random Forest trained on URL features
Author: Omar Tamer
"""

import re
import os
import math
import pickle
import urllib.parse
from typing import Dict, Any, List
from pathlib import Path


MODEL_PATH = Path(__file__).parent / "model" / "url_model.pkl"


class URLFeatureExtractor:
    """Extract numeric features from URLs for ML classification."""

    SUSPICIOUS_WORDS = [
        "login", "signin", "verify", "secure", "account", "update",
        "confirm", "banking", "paypal", "amazon", "google", "microsoft",
        "apple", "facebook", "netflix", "ebay", "credential", "password"
    ]

    SHORTENERS = [
        "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl",
        "buff.ly", "short.link", "rb.gy", "cutt.ly"
    ]

    def extract(self, url: str) -> List[float]:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")
        path = parsed.path.lower()
        full_url = url.lower()

        return [
            # Length features
            len(url),
            len(domain),
            len(path),
            len(parsed.query),

            # Character counts
            url.count("."),
            url.count("-"),
            url.count("_"),
            url.count("/"),
            url.count("?"),
            url.count("="),
            url.count("@"),
            url.count("!"),
            url.count("%"),
            url.count("+"),

            # Binary features
            int(parsed.scheme == "http"),  # no HTTPS
            int(parsed.scheme == "https"),
            int(any(s in domain for s in self.SHORTENERS)),
            int(bool(re.match(r'https?://\d+\.\d+\.\d+\.\d+', url))),  # IP in URL
            int(parsed.port is not None),
            int("%" in url),  # URL encoding

            # Domain features
            len(domain.split(".")),  # subdomain depth
            int(domain.count("-") > 1),  # multiple hyphens
            self._entropy(domain),  # domain entropy

            # Suspicious keyword count
            sum(1 for word in self.SUSPICIOUS_WORDS if word in full_url),

            # Path features
            len(path.split("/")) - 1,  # path depth
            int("login" in path or "signin" in path),
            int("admin" in path),
            int(".php" in path or ".asp" in path),

            # TLD suspiciousness
            self._suspicious_tld_score(domain),

            # Digit ratio in domain
            sum(c.isdigit() for c in domain) / (len(domain) + 1),

            # Uppercase ratio
            sum(c.isupper() for c in url) / (len(url) + 1),
        ]

    def _entropy(self, text: str) -> float:
        if not text:
            return 0
        probs = [text.count(c) / len(text) for c in set(text)]
        return -sum(p * math.log2(p) for p in probs if p > 0)

    def _suspicious_tld_score(self, domain: str) -> int:
        suspicious_tlds = [
            ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
            ".click", ".download", ".stream", ".win", ".loan"
        ]
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                return 1
        return 0

    def feature_names(self) -> List[str]:
        return [
            "url_length", "domain_length", "path_length", "query_length",
            "dot_count", "hyphen_count", "underscore_count", "slash_count",
            "question_count", "equals_count", "at_count", "exclaim_count",
            "percent_count", "plus_count",
            "is_http", "is_https", "is_shortener", "ip_in_url",
            "has_port", "has_encoding",
            "subdomain_depth", "multi_hyphen", "domain_entropy",
            "suspicious_keyword_count",
            "path_depth", "has_login_path", "has_admin_path", "has_php_asp",
            "suspicious_tld", "digit_ratio", "uppercase_ratio"
        ]


class URLClassifier:
    def __init__(self):
        self.extractor = URLFeatureExtractor()
        self.model = self._load_model()

    def _load_model(self):
        if MODEL_PATH.exists():
            with open(MODEL_PATH, "rb") as f:
                return pickle.load(f)
        return None

    def classify(self, url: str) -> Dict[str, Any]:
        features = self.extractor.extract(url)

        if self.model:
            try:
                proba = self.model.predict_proba([features])[0]
                label = self.model.predict([features])[0]
                confidence = max(proba)

                return {
                    "verdict": "MALICIOUS" if label == 1 else "LEGITIMATE",
                    "confidence": round(confidence * 100, 1),
                    "malicious_probability": round(proba[1] * 100 if len(proba) > 1 else 0, 1),
                    "method": "ml_model",
                    "feature_importances": self._top_features(features)
                }
            except Exception as e:
                pass

        # Fallback: rule-based scoring
        return self._rule_based_classify(url, features)

    def _rule_based_classify(self, url: str, features: List[float]) -> Dict[str, Any]:
        score = 0
        flags = []

        if features[14] == 1:  # is_http
            score += 10
            flags.append("No HTTPS")
        if features[16] == 1:  # is_shortener
            score += 20
            flags.append("URL shortener")
        if features[17] == 1:  # ip_in_url
            score += 30
            flags.append("IP address in URL")
        if features[23] > 2:  # suspicious_keyword_count
            score += min(features[23] * 10, 25)
            flags.append(f"{int(features[23])} suspicious keywords")
        if features[28] == 1:  # suspicious_tld
            score += 20
            flags.append("Suspicious TLD")
        if features[0] > 100:  # long URL
            score += 10
            flags.append("Unusually long URL")
        if features[22] > 4:  # high domain entropy
            score += 15
            flags.append("High domain entropy (random-looking)")
        if features[19] == 1:  # URL encoding
            score += 10
            flags.append("URL encoding detected")

        confidence = min(score + 50, 99)
        verdict = "MALICIOUS" if score >= 30 else "SUSPICIOUS" if score >= 15 else "LEGITIMATE"

        return {
            "verdict": verdict,
            "confidence": confidence,
            "malicious_probability": score,
            "method": "rule_based",
            "flags": flags
        }

    def _top_features(self, features: List[float]) -> List[str]:
        names = self.extractor.feature_names()
        if not self.model or not hasattr(self.model, "feature_importances_"):
            return []

        importances = self.model.feature_importances_
        top_indices = sorted(range(len(importances)), key=lambda i: importances[i], reverse=True)[:5]
        return [f"{names[i]} ({features[i]:.2f})" for i in top_indices]
