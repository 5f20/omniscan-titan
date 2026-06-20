from typing import Dict, Tuple, Set

PORT_SERVICES: Dict[int, Tuple[str, str, str]] = {
    21:    ("FTP",        "red",      "high"),
    22:    ("SSH",        "yellow",   "medium"),
    23:    ("Telnet",     "bold red", "critical"),
    25:    ("SMTP",       "yellow",   "medium"),
    53:    ("DNS",        "cyan",     "low"),
    80:    ("HTTP",       "green",    "low"),
    110:   ("POP3",       "yellow",   "medium"),
    111:   ("RPC",        "red",      "high"),
    135:   ("MSRPC",      "red",      "high"),
    139:   ("NetBIOS",    "red",      "high"),
    143:   ("IMAP",       "yellow",   "medium"),
    443:   ("HTTPS",      "green",    "low"),
    445:   ("SMB",        "bold red", "critical"),
    993:   ("IMAPS",      "yellow",   "medium"),
    995:   ("POP3S",      "yellow",   "medium"),
    1433:  ("MSSQL",      "bold red", "critical"),
    1521:  ("Oracle",     "red",      "high"),
    1723:  ("PPTP",       "red",      "high"),
    3306:  ("MySQL",      "red",      "high"),
    3389:  ("RDP",        "red",      "high"),
    5432:  ("PostgreSQL", "red",      "high"),
    5900:  ("VNC",        "bold red", "critical"),
    6379:  ("Redis",      "bold red", "critical"),
    8080:  ("HTTP-Proxy", "green",    "low"),
    8443:  ("HTTPS-Alt",  "green",    "low"),
    9200:  ("Elastic",    "bold red", "critical"),
    27017: ("MongoDB",    "bold red", "critical"),
}

WAF_SIGNATURES = [
    "cloudflare", "aws", "akamai", "sucuri", "incapsula",
    "f5", "imperva", "fortinet",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "OmniScan/Titan v1.0 (by 5f20) (Security Recon)",
]

HEURISTICS: Dict[str, str] = {
    r"(?i)OpenSSH_[1-7][\._]":               "CVE-202X (Outdated OpenSSH < 8.0)",
    r"(?i)Apache/2\.4\.(49|50)(?:[^0-9]|$)": "CVE-2021-41773/42013 (Path Traversal/RCE)",
    r"(?i)vsFTPd\s*2\.3\.4":                 "CVE-2011-2523 (Backdoor Command Execution)",
    r"(?i)Microsoft-IIS/[1-5]\.":            "Critically Outdated IIS Version",
    r"(?i)ProFTPD\s*1\.3\.5(?:[^0-9]|$)":    "CVE-2015-3306 (mod_copy RCE)",
}

# Allowlist of nmap flags safe to pass via --nmap-args.
SAFE_NMAP_FLAGS: Set[str] = {
    "-sV", "-sC", "-sS", "-sT", "-sU", "-sN", "-sF", "-sX",
    "-Pn", "-n", "-R", "-6",
    "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
    "--version-light", "--version-all", "--version-intensity",
    "--open", "--reason",
    "-A",
}

# Sentinel used to signal workers to stop.
_SENTINEL = object()
