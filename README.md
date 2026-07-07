<div align="center">

# ⚡ OmniScan Titan
**Tactical Network Intelligence & Automated Vulnerability Mapping Framework**

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Engine: Asynchronous](https://img.shields.io/badge/Engine-Asynchronous-success.svg?style=for-the-badge)](https://docs.python.org/3/library/asyncio.html)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/144i)

<br>

![OmniScan Titan Live Terminal Demo](assets/pristine_demo.gif)

</div>

---

## 📖 The "Why"

In modern network engagements, **speed** and **stealth** are everything. Traditional scanners like Nmap are accurate but agonizingly slow across massive subnets. Masscan is fast but lacks deep-packet inspection.

**OmniScan Titan bridges this gap.** Built on Python's `asyncio` event loop, Titan multiplexes thousands of raw socket connections to sweep vast digital footprints in seconds. It maps the perimeter, then seamlessly funnels *only* confirmed open ports into a sandboxed Nmap subprocess. 

**Masscan speed. Nmap intelligence.**

---

## 🦅 Tactical Capabilities

| Feature | Description |
| :--- | :--- |
| 🚀 **Async Multiplexing** | Sweeps tens of thousands of ports concurrently. Zero operating system file descriptor exhaustion. |
| 🧠 **Hybrid Engine** | Raw async socket discovery mapped directly to Nmap's Deep Packet Inspection (DPI). |
| 🛡️ **Heuristic Fingerprinting** | Instantly flags critically outdated software and known CVEs straight from raw banners. |
| 🔍 **Context-Aware** | Rips SSL certificates (flagging MitM risks), parses HTTP server headers, and detects WAFs. |
| 📊 **Real-Time Telemetry** | $O(1)$ memory-optimized terminal UI providing live, color-coded intelligence routing. |

---

## ⚙️ Deployment

**Prerequisites:** Python 3.8+ and `nmap` installed on the host OS.

```bash
# Clone the repository
git clone [https://github.com/5f20/omniscan-titan.git](https://github.com/5f20/omniscan-titan.git)

# Navigate into the directory
cd omniscan-titan

# Install dependencies
pip install -r requirements.txt

```

---

## 🎯 Rules of Engagement

### 1. The Ghost Sweep (Speed Mode)

Maps the network blazingly fast using purely asynchronous sockets. Bypasses Nmap entirely.

```bash
python3 main.py -t 192.168.1.0/24 -p "80,443,8080-8090" -m async

```

### 2. The Deep Audit (Hybrid Engine)

Async discovery finds open ports, then hands them off to Nmap for deep service scanning.

```bash
python3 main.py -t scanme.nmap.org -p "top" -m hybrid -oH intelligence_report.html

```

### 3. Large-Scale Enterprise Scope

Ingests targets from a file, ramps up concurrency, and exports clean JSON without blocking the async loop.

```bash
python3 main.py -iL scope_targets.txt -p "1-10000" -m hybrid -w 2000 -oJ data.json 

```

---

## 📊 Intelligence Exporting

Titan supports comprehensive data exfiltration via non-blocking background threads:

* 📄 `-oH report.html` : Boardroom-ready HTML report.
* 💻 `-oJ report.json` : Clean JSON output for SIEM ingestion.
* 🗃️ `-oS report.sqlite` : Dumps directly into a local SQLite database.
* 📈 `-oC report.csv` : Standardized CSV (Protected with Macro/Formula Injection sanitization).

---

## 🛡️ Architecture & Performance Patches

* **Lock Contention Eradication:** UI strings and regex matches are pre-computed outside the global lock, allowing the async engine to run at maximum concurrency.
* **Deadlock & Infinite Loop Prevention:** Strict token bucket bounds instantly reject impossible packet rates, and asynchronous sleeping is handled outside lock contexts to prevent worker freezing.
* **$O(1)$ Telemetry Memory:** Live discovery feeds utilize fixed-length double-ended queues (`deque`), eliminating heavy $O(n)$ list shifting during rapid discovery events.
* **Non-Blocking Disk I/O:** All JSON and CSV data dumping is securely offloaded to background execution threads, ensuring large network sweeps never freeze while writing to disk.
* **Socket Hygiene:** Forces immediate termination of dirty TCP connections after partial banner grabs to keep the connection pool pristine.

---

## ☕ Support the Development

If this tool has saved you time during a security engagement, helped secure your infrastructure, or you simply appreciate high-performance Python engineering, consider supporting the caffeine pipeline:

---

## ⚖️ Legal Disclaimer

**For Educational and Authorized Testing Purposes Only.** OmniScan Titan is designed strictly for authorized security professionals. The developers assume **no liability** for any misuse, damage, or illegal activity caused by this tool.

*Released under the [MIT License](https://www.google.com/search?q=LICENSE).*
