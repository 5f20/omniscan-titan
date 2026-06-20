# ⚡ OmniScan Titan

![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Mode: Asynchronous](https://img.shields.io/badge/Engine-Asynchronous-success.svg)
![Build: Passing](https://img.shields.io/badge/Build-Passing-brightgreen.svg)

> **Tactical Network Intelligence & Automated Vulnerability Mapping Framework**

In modern network engagements, speed and stealth are everything. Traditional scanners are bloated and slow, often tripping alarms before the reconnaissance phase is even complete. **OmniScan Titan** was engineered to solve this.

Built from the ground up on Python's `asyncio` event loop, Titan utilizes multiplexed socket connections to sweep vast digital footprints in seconds. Once the perimeter is mapped, it seamlessly hands off active ports to a sandboxed Nmap subprocess, ensuring deep-packet inspection only occurs where it matters.

## 🦅 Tactical Capabilities

* **Asynchronous Multiplexing:** Capable of sweeping tens of thousands of ports concurrently without exhausting operating system file descriptors.
* **Hybrid Inspection Engine (HIE):** Connects raw socket discovery with Nmap's Deep Packet Inspection. Find the open doors instantly, then interrogate them thoroughly.
* **Heuristic Fingerprinting:** Instantly flags critically outdated software and known CVEs (e.g., outdated OpenSSH, Apache path traversal, Mod_copy RCE) directly from raw banners.
* **Context-Aware Protocol Analysis:** Distinguishes between HTTP, HTTPS, and raw TCP. Automatically extracts SSL certificate common names, HTTP server headers, and detects active Web Application Firewalls (WAFs) like Cloudflare, Imperva, and AWS.
* **Real-Time Telemetry:** A Rich-powered terminal interface providing live, color-coded intelligence routing and statistical analysis as the scan progresses.

## 🏗️ Architecture Overview

Unlike legacy synchronous scanners that wait for timeouts, Titan operates on a non-blocking asynchronous matrix. 
1. **Phase 1 (Discovery):** Thousands of lightweight workers fire parallel connection requests to the target pool.
2. **Phase 2 (Interrogation):** Active sockets attempt smart banner grabbing. If HTTPS is detected, it auto-negotiates SSL/TLS to rip the underlying certificate data.
3. **Phase 3 (Handoff):** Confirmed active ports are securely passed via temporary file descriptors to the Nmap engine for secondary validation.

## ⚙️ Deployment Instructions

**Prerequisites:** Python 3.8+ and `nmap` installed on the host OS.

```text
git clone https://github.com/5f20/omniscan-titan.git
cd omniscan-titan
pip install -r requirements.txt
```

## 🎯 Rules of Engagement (Usage)

OmniScan Titan requires specific targets and port ranges. It can ingest single IPs, CIDR blocks, or massive text files of aggregated targets.

**1. High-Speed Asynchronous Sweep (No Nmap):**
```text
python3 main.py -t 192.168.1.0/24 -p "80,443,8080-8090" -m async
```

**2. The Hybrid Approach (Async Discovery + Nmap DPI):**
```text
python3 main.py -t scanme.nmap.org -p "top" -m hybrid -oH intelligence_report.html
```

**3. Large-Scale Infrastructure Audit:**
```text
python3 main.py -iL scope_targets.txt -p "1-10000" -m hybrid -oJ data.json -w 2000
```

## 📊 Intelligence Exporting

Titan supports comprehensive data exfiltration for post-engagement reporting:
* `-oH report.html`: Generates a visually styled, boardroom-ready HTML report.
* `-oJ report.json`: Clean JSON output for feeding into other automated SIEMs or pipelines.
* `-oC report.csv`: Standardized CSV for spreadsheet analysis.
* `-oS report.sqlite`: Dumps intelligence directly into a local relational database.

## ☕ Support the Development

If this tool has saved you time during a security engagement, helped secure your infrastructure, or you simply appreciate high-performance Python engineering, consider supporting the caffeine pipeline:

<a href="https://buymeacoffee.com/144i" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 50px !important;width: 217px !important;">
</a>

## ⚖️ Legal Disclaimer (Hacker Ethics)

**For Educational and Authorized Testing Purposes Only.**
OmniScan Titan is designed strictly for security professionals, system administrators, and researchers to audit networks and applications they own or have explicit, written permission to test. The developers assume **no liability** and are not responsible for any misuse, damage, or illegal activity caused by this tool. Do not point this weapon at infrastructure you do not own.

## 📄 License
Released under the MIT License.
