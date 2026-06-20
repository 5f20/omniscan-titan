# ⚡ OmniScan Titan

> **Enterprise-grade Asynchronous Network Intelligence & Reconnaissance Framework**

OmniScan Titan is a high-performance network scanning and banner-grabbing engine. Built with Python's `asyncio`, it leverages an asynchronous matrix for rapid socket connections and seamlessly hands off deep packet inspection tasks to Nmap via a hybrid scanning mode.

## 🚀 Key Features
* **Asynchronous Socket Engine:** Capable of sweeping thousands of ports concurrently.
* **Hybrid DPI Engine:** Automatically pipes open ports into a sandboxed Nmap subprocess.
* **Smart Banner Grabbing:** Context-aware HTTP/HTTPS analysis and WAF detection.
* **Heuristic Vulnerability Mapping:** Instantly flags critically outdated software and known CVEs.
* **Rich Terminal UI:** Real-time telemetry, progress tracking, and color-coded reporting.

## ⚙️ Installation
**Prerequisites:** Python 3.8+ and `nmap` installed on your system.

```text
git clone https://github.com/5f20/omniscan-titan.git
cd omniscan-titan
pip install rich defusedxml
```

## 🛠️ Usage
**Basic Asynchronous Scan:**
```text
python3 main.py -t 192.168.1.0/24 -p "80,443,8080" -m async
```
**Hybrid Deep Inspection Scan:**
```text
python3 main.py -t scanme.nmap.org -p "top" -m hybrid -oH report.html
```

## ⚠️ Legal Disclaimer
**For Educational and Authorized Testing Purposes Only.**
The developers assume **no liability** and are not responsible for any misuse or illegal activity caused by this tool. Do not use without explicit authorization.

## 📄 License
MIT License
