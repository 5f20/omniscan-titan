import json
import csv
import sqlite3
import html
from datetime import datetime
from typing import Dict, Any
from rich.console import Console

console = Console()

def export_results(results: Dict[str, Dict[int, Dict[str, Any]]], args: Any) -> None:
    clean = {h: p for h, p in results.items() if p}
    if not clean:
        return

    if args.out_json:
        with open(args.out_json, "w", encoding="utf-8") as f:
            json.dump(clean, f, indent=4)
        console.print(f"[+] Exported JSON  → [bold green]{args.out_json}[/bold green]")

    if args.out_csv:
        with open(args.out_csv, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Host", "Port", "State", "Service", "Info", "Vulnerabilities"])
            for h, ports in clean.items():
                for pt, d in ports.items():
                    w.writerow([
                        h, pt, d["state"], d["service"], d["info"],
                        ", ".join(d.get("vulns", [])),
                    ])
        console.print(f"[+] Exported CSV   → [bold green]{args.out_csv}[/bold green]")

    if args.out_sql:
        conn = sqlite3.connect(args.out_sql)
        c = conn.cursor()
        c.execute(
            """CREATE TABLE IF NOT EXISTS scans
               (timestamp TEXT, host TEXT, port INTEGER, state TEXT,
                service TEXT, info TEXT, vulns TEXT)"""
        )
        now = datetime.now().isoformat()
        for h, ports in clean.items():
            for pt, d in ports.items():
                c.execute(
                    "INSERT INTO scans VALUES (?,?,?,?,?,?,?)",
                    (
                        now, h, pt, d["state"], d["service"], d["info"],
                        ", ".join(d.get("vulns", [])),
                    ),
                )
        conn.commit()
        conn.close()
        console.print(f"[+] Exported SQLite → [bold green]{args.out_sql}[/bold green]")

    if args.out_html:
        rows = ""
        for h, ports in clean.items():
            for pt, d in ports.items():
                safe_h    = html.escape(h)
                safe_srv  = html.escape(str(d["service"]))
                safe_info = html.escape(str(d["info"]))
                vulns     = html.escape(", ".join(d.get("vulns", [])))
                vuln_cell = f"<td class='vuln'>{vulns}</td>" if vulns else "<td>None</td>"
                rows += (
                    f"<tr><td>{safe_h}</td><td>{pt}/tcp</td>"
                    f"<td>{safe_srv}</td><td>{safe_info}</td>{vuln_cell}</tr>\n"
                )
        html_doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Titan Security Report</title>
<style>
  body  {{ font-family: Arial, sans-serif; background: #0f0f1b; color: #fff; margin: 30px; }}
  h1   {{ color: #00ffcc; border-bottom: 2px solid #333; padding-bottom: 10px; }}
  table{{ border-collapse: collapse; width: 100%; margin-top: 20px; background: #1a1a2e; }}
  th, td {{ border: 1px solid #333; padding: 12px; text-align: left; }}
  th   {{ background: #16213e; color: #00ffcc; }}
  tr:nth-child(even) {{ background: #131324; }}
  .vuln{{ color: #ff4d4d; font-weight: bold; }}
</style>
</head><body>
<h1>⚡ OmniScan Titan (by 5f20) — Intelligence Report</h1>
<p><strong>Date:</strong> {html.escape(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</p>
<table>
  <tr><th>Host</th><th>Port</th><th>Service</th><th>Banner / Intelligence</th>
  <th>Vulnerabilities</th></tr>
{rows}
</table></body></html>"""
        with open(args.out_html, "w", encoding="utf-8") as f:
            f.write(html_doc)
        console.print(f"[+] Exported HTML  → [bold green]{args.out_html}[/bold green]")

    if args.out_md:
        lines = [
            "# ⚡ OmniScan Titan (by 5f20) — Reconnaissance Report",
            f"\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n",
            "| Host | Port | Service | Info | Vulnerabilities |",
            "|------|------|---------|------|-----------------|",
        ]
        for h, ports in clean.items():
            for pt, d in ports.items():
                safe_h    = html.escape(h)
                safe_srv  = html.escape(str(d["service"]))
                safe_info = html.escape(str(d["info"])).replace("|", "&#124;")
                vulns = html.escape(", ".join(d.get("vulns", []))).replace("|", "&#124;")
                lines.append(f"| {safe_h} | {pt}/tcp | {safe_srv} | {safe_info} | {vulns or 'None'} |")
        with open(args.out_md, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        console.print(f"[+] Exported MD    → [bold green]{args.out_md}[/bold green]")
