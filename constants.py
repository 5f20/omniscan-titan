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

# Payload injection for deep UDP state verification
UDP_PAYLOADS: Dict[int, bytes] = {
    53:   b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03", # DNS BIND version request
    161:  b"\x30\x14\x02\x01\x00\x04\x06public\xa0\x07\x02\x01\x00\x02\x01\x00\x02\x01\x00", # SNMP Public v1 walk
    123:  b"\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # NTP v4 Client Request
    137:  b"\x80\xF0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01", # NetBIOS NBSTAT
    500:  b"\x00\x11\x22\x33\x44\x55\x66\x77\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\xC0", # IKE VPN Handshake Start
}

WAF_SIGNATURES = [
    "cloudflare", "aws", "akamai", "sucuri", "incapsula",
    "f5", "imperva", "fortinet", "barracuda", "mod_security"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "OmniScan/Titan v2.0 (by 5f20) (Security Recon)",
]

# Privacy DOH Providers (DNS over HTTPS)
DOH_PROVIDERS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve"
]

HEURISTICS: Dict[str, str] = {
    r"(?i)OpenSSH_[1-7][\._]":               "CVE-202X (Outdated OpenSSH < 8.0)",
    r"(?i)Apache/2\.4\.(49|50)(?:[^0-9]|$)": "CVE-2021-41773/42013 (Path Traversal/RCE)",
    r"(?i)vsFTPd\s*2\.3\.4":                 "CVE-2011-2523 (Backdoor Command Execution)",
    r"(?i)Microsoft-IIS/[1-5]\.":            "Critically Outdated IIS Version",
    r"(?i)ProFTPD\s*1\.3\.5(?:[^0-9]|$)":    "CVE-2015-3306 (mod_copy RCE)",
    r"(?i)Redis\s*server\s*v=[1-4]\.":       "Legacy Redis (Potential Unauth Access)",
    r"(?i)MongoDB\s*[1-3]\.":                "Legacy MongoDB (No Auth by default)",
}

SAFE_NMAP_FLAGS: Set[str] = {
    "-sV", "-sC", "-sS", "-sT", "-sU", "-sN", "-sF", "-sX",
    "-Pn", "-n", "-R", "-6",
    "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
    "--version-light", "--version-all", "--version-intensity",
    "--open", "--reason", "--script",
    "-A", "-O"
}

_SENTINEL = object()
