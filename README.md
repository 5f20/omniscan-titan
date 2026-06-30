<div align="center">

# ⚡ OmniScan Titan

**Tactical Network Intelligence & Automated Vulnerability Mapping Framework**

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Engine: Asynchronous](https://img.shields.io/badge/Engine-Asynchronous-success.svg?style=for-the-badge)](https://docs.python.org/3/library/asyncio.html)
[![Contributions Welcome](https://img.shields.io/badge/Contributions-Welcome-brightgreen.svg?style=for-the-badge)](#)

<img src="https://raw.githubusercontent.com/5f20/omniscan-titan/main/assets/demo.gif" alt="OmniScan Titan Live Terminal Demo" width="800" style="border-radius: 10px; box-shadow: 0 4px 8px rgba(0,0,0,0.2); margin-top: 20px; margin-bottom: 20px;">
<br>
*(Replace this placeholder URL with an actual GIF of your tool running. Tools like VHS or Asciinema are great for this)*

</div>

---

## 📖 The "Why"
In modern network engagements, **speed** and **stealth** are everything. Traditional scanners like Nmap are incredibly accurate but agonizingly slow across massive subnets. Stateless scanners like Masscan are lightning-fast but lack deep-packet inspection and application-layer context.

**OmniScan Titan bridges this gap.** Built from the ground up on Python's `asyncio` event loop, Titan multiplexes thousands of raw socket connections to sweep vast digital footprints in seconds. Once the perimeter is mapped, it seamlessly funnels *only* the confirmed open ports into a sandboxed Nmap subprocess. 

**The result? Masscan speed combined with Nmap intelligence.**

---

## 🦅 Tactical Capabilities

| Feature | Description |
| :--- | :--- |
| 🚀 **Asynchronous Multiplexing** | Sweeps tens of thousands of ports concurrently without exhausting operating system file descriptors or creating thread-lock bottlenecks. |
| 🧠 **Hybrid Inspection Engine** | Connects raw async socket discovery with Nmap's Deep Packet Inspection (DPI). Finds the open doors instantly, then interrogates them thoroughly. |
| 🛡️ **Heuristic Fingerprinting** | Instantly flags critically outdated software and known CVEs (e.g., outdated OpenSSH, Apache path traversal, Mod_copy RCE) directly from raw banners. |
| 🔍 **Context-Aware Protocol Analysis** | Distinguishes between HTTP, HTTPS, and raw TCP. Automatically rips SSL certificates (flagging MitM risks), parses HTTP server headers, and detects WAFs (Cloudflare, Imperva, AWS). |
| 📊 **Real-Time Telemetry** | A rich, terminal-based UI providing live, color-coded intelligence routing and statistical analysis as the scan progresses. |

---

## 🏗️ Architecture Overview

Unlike legacy synchronous scanners that wait for timeouts, Titan operates on a non-blocking asynchronous matrix. 

<div align="center">
  <img src="https://i.imgur.com/EpKmpNy.png" alt="OmniScan Titan Architecture" width="800" style="border-radius: 10px; box-shadow: 0 4px 8px rgba(0,0,0,0.2); margin-top: 20px; margin-bottom: 20px;">
</div>

1. **Phase 1 (Discovery):** Thousands of lightweight workers fire parallel connection requests to the target pool.
2. **Phase 2 (Interrogation):** Active sockets attempt smart banner grabbing. If HTTPS is detected, it auto-negotiates SSL/TLS to rip the underlying certificate data.
3. **Phase 3 (Handoff):** Confirmed active ports are securely batched via temporary file descriptors to the Nmap engine for secondary validation.

---

## ⚙️ Deployment Instructions

**Prerequisites:** Python 3.8+ and `nmap` installed on the host OS.

```bash
# Clone the repository
git clone https://github.com/5f20/omniscan-titan.git

# Navigate into the directory
cd omniscan-titan

# Install dependencies (Rich, DefusedXML)
pip install -r requirements.txt
```

---

## 🎯 Rules of Engagement (Usage)

OmniScan Titan requires specific targets and port ranges. It can ingest single IPs, CIDR blocks, or massive text files of aggregated targets.

### 1. The Ghost Sweep (Speed Mode)
Maps the network blazingly fast using purely asynchronous sockets. Bypasses Nmap DPI entirely. Great for initial perimeter mapping.
```bash
python3 main.py -t 192.168.1.0/24 -p "80,443,8080-8090" -m async
```

### 2. The Deep Audit (Hybrid Engine)
The recommended approach. Async discovery instantly finds open ports, then hands them off to Nmap for deep service and script scanning. Outputs a boardroom-ready HTML report.
```bash
python3 main.py -t scanme.nmap.org -p "top" -m hybrid -oH intelligence_report.html
```

### 3. Large-Scale Enterprise Scope
Ingests thousands of targets from a file, ramps up concurrency to 2000 workers, and exports clean JSON for SIEM ingestion.
```bash
python3 main.py -iL scope_targets.txt -p "1-10000" -m hybrid -w 2000 -oJ data.json 
```

---

## 📊 Intelligence Exporting

Titan supports comprehensive data exfiltration tailored for post-engagement reporting, pipeline automation, or spreadsheet analysis:

* 📄 `-oH report.html` : Generates a visually styled, dark-mode, boardroom-ready HTML report.
* 💻 `-oJ report.json` : Clean JSON output for feeding into Splunk, ELK, or custom automated SIEMs.
* 🗃️ `-oS report.sqlite` : Dumps intelligence directly into a local SQLite relational database for SQL querying.
* 📈 `-oC report.csv` : Standardized CSV for spreadsheet analysis (Protected with strict Excel Macro/Formula Injection sanitization).
* 📝 `-oM report.md` : Beautifully formatted Markdown tables.

---

## 🛡️ Recent Security & Performance Patches
* **Nmap Fork-Bomb Protection:** Implemented strictly bound Async Semaphores to prevent memory/CPU exhaustion when analyzing networks with thousands of open ports.
* **DOM Bomb Protection:** Migrated to iterative XML parsing (`ET.iterparse`) to prevent memory exhaustion on gigabyte-sized Nmap outputs.
* **Smart TLS Fallback:** Upgraded the HTTP analyzer to attempt strict TLS verification first, falling back to unverified contexts while securely flagging MitM risks without double-handshaking.
* **Zombie Process Eradication:** Implemented asynchronous cancellation traps to gracefully kill child Nmap binaries on user interrupts (`CTRL+C`).

---

## ☕ Support the Development

If this tool has saved you time during a security engagement, helped secure your infrastructure, or you simply appreciate high-performance Python engineering, consider supporting the caffeine pipeline:

<a href="https://buymeacoffee.com/144i" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 50px !important;width: 217px !important;">
</a>

---

## ⚖️ Legal Disclaimer (Hacker Ethics)

**For Educational and Authorized Testing Purposes Only.**  
OmniScan Titan is designed strictly for security professionals, system administrators, and researchers to audit networks and applications they own or have explicit, written permission to test. The developers assume **no liability** and are not responsible for any misuse, damage, or illegal activity caused by this tool. Do not point this weapon at infrastructure you do not own.

*Released under the [MIT License](LICENSE).*
