# 🛡️ Phishing Defense, Simulation, and Forensic Analysis Toolkit

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/gophish/gophish)](https://github.com/gophish/gophish/releases/latest)

## 📝 Overview

This repository aggregates essential tools and outlines a structured methodology for **cybersecurity professionals** and **security awareness trainers** to conduct legitimate, defensive phishing simulations (using frameworks like GoPhish) and perform **forensic analysis** on collected phishing samples.

The methodology focuses on understanding the attack chain from creation to analysis to build stronger organizational defenses.

---

## 1. 🎣 Phishing Simulation Framework (GoPhish)

**GoPhish** is an open-source phishing framework designed for legitimate security awareness training and penetration testing.

| Platform | Download Link |
| :--- | :--- |
| **Linux (32-bit)** | `https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-32bit.zip` |
| **Linux (64-bit)** | `https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip` |
| **macOS (64-bit)** | `https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-osx-64bit.zip` |
| **Windows (64-bit)** | `https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-windows-64bit.zip` |
| **Source Code (ZIP)** | `https://github.com/gophish/gophish/archive/refs/tags/v0.12.1.zip` |
| **Source Code (TAR.GZ)** | `https://github.com/gophish/gophish/archive/refs/tags/v0.12.1.tar.gz` |

---

## 2. 🔍 Most Important Tools for Phishing Analysis

These tools are crucial for examining suspicious files, links, and code snippets from phishing samples.

| Tool | Purpose | Link |
| :--- | :--- | :--- |
| **PhishTool** | In-depth email message and header forensics. | `https://www.phishtool.com/` |
| **VirusTotal** | Checking the reputation of files, IPs, and URLs against multiple security vendors. | `https://www.virustotal.com/gui/` |
| **CyberChef** | A "Swiss Army Knife" for data—ideal for decoding, decompressing, and analyzing payloads. | `https://gchq.github.io/CyberChef/` |
| **Any.Run** | Interactive sandbox for malware analysis, allowing safe execution of malicious payloads. | `https://app.any.run/` |

---

## 3. 📧 Tools for Email Header Analysis

Analyzing email headers is key to identifying the true sender, mail flow path, and authentication results (SPF, DKIM, DMARC).

* **MailHeader:** `https://mailheader.org/`
* **Messageheader (Google Apps Toolbox):** `https://toolbox.googleapps.com/apps/messageheader/analyzeheader`
* **Message Header Analyzer:** `https://mha.azurewebsites.net/`

---

## 4. 🌐 Tools for IP and URL/Link Analysis

Used to gather threat intelligence and check the reputation of infrastructure used in phishing campaigns.

### **Tool for Information of IP**

* **IPinfo.io:** `https://ipinfo.io/` - Provides detailed information about an IP address, including geolocation, host, and network owner.

### **Tools for URL/Link Analysis**

* **URLScan.io:** `https://urlscan.io/` - Scans and analyzes websites, providing screenshots, DOM, and network requests.
* **URL2PNG:** `https://www.url2png.com/` - Captures a screenshot of a webpage. (Useful for visual verification without direct browsing.)
* **Wannabrowser:** `https://www.wannabrowser.net/` - Safely renders URLs to check their content.
* **Talos Reputation Center:** `https://talosintelligence.com/reputation` - Checks the reputation of IPs and domains based on Cisco Talos intelligence.

---

## 🔬 Phishing Analysis Methodology: 5 Phases

The following steps outline a standard procedure for conducting a defensive phishing exercise and performing incident response on a collected sample.

### Phase 1 — Planning & Sample Collection

* **Define Objectives:** Clearly state what is being tested (e.g., sender spoofing, malicious links, attachments) and the success metrics.
* **Sample Collection:** Collect representative raw phishing samples (e.g., as `.eml` files) for forensic examination.

### Phase 2 — Phish Creation (Gophish)

* **Build Components:** Use **GoPhish** to create realistic, controlled phishing emails and landing pages.
* **Simulation Setup:** Configure the platform to simulate email delivery, track user clicks, and capture credentials or payload behavior for analysis.

### Phase 3 — Delivery & Testing

* **Execution:** Send the controlled phishing campaign to designated test accounts.
* **Monitoring:** Monitor delivery results and ensure the raw email files are saved for subsequent steps.

### Phase 4 — Header & Sender Analysis

* **Forensics:** Analyze the raw email headers and sender metadata, focusing on the `Return-Path`, `Received` chain, and email authentication results (SPF/DKIM/DMARC).
* **Tools:** Utilize **Google’s Message Header Analyzer** and **PhishTool** for detailed message forensics and visualization.

### Phase 5 — Link & URL Scanning

* **Extraction:** Extract and inspect all links and attachments from the collected samples.
* **Reputation Check:** Scan all suspicious URLs, files, and domains using **VirusTotal** and **URLScan.io** to check for known malicious reputations and analyze payload activity.
