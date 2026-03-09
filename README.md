# 🛡️ PhishGuard AI

<div align="center">

```
██████╗ ██╗  ██╗██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗      █████╗ ██╗
██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗    ██╔══██╗██║
██████╔╝███████║██║███████╗███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║    ███████║██║
██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║    ██╔══██║██║
██║     ██║  ██║██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝    ██║  ██║██║
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝     ╚═╝  ╚═╝╚═╝
```

**Advanced AI/ML Phishing Detection & Threat Intelligence CLI Tool**

![Python](https://img.shields.io/badge/Python-3.9+-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=flat-square&logo=kalilinux)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![Made By](https://img.shields.io/badge/Made%20by-Omar%20Tamer-red?style=flat-square)

</div>

---

## 🎯 What is PhishGuard AI?

**PhishGuard AI** is a powerful command-line phishing detection and threat intelligence tool built for cybersecurity professionals, red teams, blue teams, and SOC analysts. It combines **machine learning**, **statistical AI-text detection**, and **live threat intelligence APIs** to analyze emails, URLs, domains, and file attachments for phishing indicators.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 📧 **Email Analysis** | Parse `.eml` files — headers, SPF/DKIM/DMARC, spoofing detection, urgency language |
| 🔗 **URL Analysis** | Typosquatting, subdomain abuse, redirect chains, homograph attacks |
| 🤖 **AI Text Detection** | Detect LLM-generated phishing emails using perplexity & burstiness analysis |
| 🧠 **ML URL Classifier** | Random Forest model trained on phishing datasets (96%+ accuracy) |
| 🌐 **Domain Intelligence** | WHOIS age, DNS records, blacklist checks, SSL analysis, lookalike detection |
| 🔍 **VirusTotal** | Scan URLs, domains, IPs, and files across 70+ AV engines |
| 🚨 **AbuseIPDB** | Check IPs for abuse reports, phishing history, TOR exit nodes |
| 📸 **Screenshots** | Capture and analyze website screenshots for brand impersonation |
| 📄 **JSON Export** | Export full reports for SIEM integration (Splunk, ELK, etc.) |

---

## 🚀 Installation

### Prerequisites
- Kali Linux (or any Debian-based system)
- Python 3.9+
- pip

### Install

```bash
# Clone the repo
git clone https://github.com/Omar-tamerr/phishguard
cd phishguard

# Install dependencies
pip install -r requirements.txt

# Install browser for screenshots
playwright install chromium

# Install as global CLI tool
pip install -e .

# Train ML model (optional but recommended)
phishguard --train
```

---

## 📖 Usage

### 🔑 Configure API Keys (one time)
```bash
phishguard --config --vt-key YOUR_VIRUSTOTAL_KEY --abuse-key YOUR_ABUSEIPDB_KEY
```

Get free API keys:
- VirusTotal: https://www.virustotal.com/gui/join-us
- AbuseIPDB: https://www.abuseipdb.com/register

---

### 📧 Analyze a Suspicious Email
```bash
phishguard --email suspicious.eml --screenshot --report report.json
```

### 🔗 Scan a URL
```bash
phishguard --url "http://paypa1-verify.com/login"
```

### 📁 Scan a File/Attachment
```bash
phishguard --file attachment.pdf
```

### 🌐 Domain Intelligence
```bash
phishguard --domain "paypa1-verify.com"
```

### 🧠 Train ML Model
```bash
# Add your dataset to data/phishing_urls.csv (columns: url, label)
phishguard --train
```

---

## 📊 Sample Output

```
╔══════════════════════════════════════════════════════╗
║        🛡️  PhishGuard AI v1.0 — Scan Report          ║
╚══════════════════════════════════════════════════════╝

📧 EMAIL ANALYSIS
  SPF      ❌ FAIL
  DKIM     ❌ MISSING  
  DMARC    ❌ MISSING
  Spoofing 🔴 Reply-To domain mismatch detected

🤖 AI TEXT DETECTION
  AI Score    87% — LIKELY AI GENERATED
  Burstiness  0.12 (very uniform = AI-like)
  Phrases     "please verify immediately", "your account will be"

🔗 URL ANALYSIS
  ML Verdict  🔴 MALICIOUS (96.2% confidence)
  Typosquatting  Mimics 'paypal' (94% similar)

🌐 DOMAIN INTELLIGENCE
  Age         3 days old 🔴
  Blacklists  LISTED on PhishTank, URLhaus

🔴 RISK SCORE: 97/100 — PHISHING CONFIRMED
```

---

## 🏗️ Architecture

```
phishguard/
├── phishguard.py           # Main CLI entry point
├── core/
│   ├── email_analyzer.py   # Email headers + auth checks
│   ├── url_analyzer.py     # URL pattern analysis
│   ├── domain_reputation.py # WHOIS + DNS + blacklists
│   ├── virustotal.py       # VirusTotal API integration
│   ├── abuseipdb.py        # AbuseIPDB API integration
│   ├── ai_text_detector.py # LLM-text statistical detection
│   └── screenshot_analyzer.py # Visual analysis
├── ml/
│   ├── url_classifier.py   # Random Forest classifier
│   └── train.py            # Model training pipeline
└── utils/
    └── report.py           # Rich CLI + JSON reporting
```

---

## 🤖 AI/ML Details

### URL Classifier
- **Algorithm**: Random Forest (200 estimators)
- **Features**: 31 URL-derived features (length, entropy, keywords, TLD, etc.)
- **Training Data**: PhishTank + Alexa Top 1M (or custom CSV)
- **Accuracy**: ~96% F1 on balanced test set

### AI Text Detector
Detects LLM-generated phishing emails using:
- **Perplexity**: Measures predictability (AI = lower perplexity)
- **Burstiness**: Sentence length variation (AI = more uniform)
- **Phrase patterns**: GPT-style connectors and formal language
- **Contraction ratio**: AI rarely uses contractions
- **Formality score**: AI over-uses formal language

---

## 🛠️ For Red Teams

PhishGuard AI helps red teams:
- **Assess email security posture** of target organizations
- **Test if your phishing simulations** would be flagged by detection tools
- **Build threat intelligence reports** for clients
- **Train employees** by showing them scored phishing examples

---

## 📜 Legal Disclaimer

> This tool is intended for **authorized security testing, research, and educational purposes only**. Always obtain written permission before testing any systems or email infrastructure you do not own. The author assumes no liability for misuse.

---

## 👨‍💻 Author

**Omar Tamer**  
Cybersecurity Researcher | Red Team | Penetration Tester

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
