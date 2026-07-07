import json
import csv
import html
from datetime import datetime
from typing import Dict, Any, Iterable
import aiosqlite
from rich.console import Console

console = Console()

def _sanitize_csv(value: Any) -> str:
    """Neutralizes CSV Macro/Formula Injection payloads."""
    if value is None: 
        return ""
    val_str = str(value)
    if val_str.startswith(("=", "+", "-", "@", "\t", "\r")):
        return f"'{val_str}"
    return val_str

async def export_json_stream(path: str, items: Iterable[Dict[str, Any]]):
    def _write_json():
        with open(path, "w", encoding="utf-8") as f:
            f.write("[\n")
            first = True
            for item in items:
                if not first: 
                    f.write(",\n")
                json.dump(item, f, ensure_ascii=False)
                first = False
            f.write("\n]\n")
            
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _write_json)
    console.print(f"[+] Exported JSON Stream -> [bold green]{path}[/bold green]")

async def export_csv_stream(path: str, items: Iterable[Dict[str, Any]]):
    """Streams data sequentially to CSV format."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Host", "Port", "State", "Service", "Info", "Vulnerabilities"])
        for it in items:
            w.writerow([
                _sanitize_csv(it.get("host")), 
                it.get("port"), 
                _sanitize_csv(it.get("state")),
                _sanitize_csv(it.get("service")), 
                _sanitize_csv(it.get("info")),
                _sanitize_csv(", ".join(it.get("vulns", []))),
            ])
    console.print(f"[+] Exported CSV Stream  -> [bold green]{path}[/bold green]")

async def export_sqlite(path: str, items: Iterable[Dict[str, Any]]):
    """Ingests streaming results directly into a local SQLite database."""
    async with aiosqlite.connect(path) as db:
        await db.execute(
            """CREATE TABLE IF NOT EXISTS scans
               (timestamp TEXT, host TEXT, port INTEGER, state TEXT, service TEXT, info TEXT, vulns TEXT)"""
        )
        now = datetime.now().isoformat()
        rows = [(now, it.get("host"), it.get("port"), it.get("state"), it.get("service"), it.get("info"), ", ".join(it.get("vulns", []))) for it in items]
        await db.executemany("INSERT INTO scans VALUES (?,?,?,?,?,?,?)", rows)
        await db.commit()
    console.print(f"[+] Exported SQLite DB   -> [bold green]{path}[/bold green]")

def export_html(path: str, items: Iterable[Dict[str, Any]]):
    """Generates a styled, dark-mode HTML report from the result stream."""
    rows = ""
    for it in items:
        safe_h = html.escape(str(it.get("host", "")))
        safe_srv = html.escape(str(it.get("service", "")))
        safe_info = html.escape(str(it.get("info", "")))
        vulns = html.escape(", ".join(it.get("vulns", [])))
        vuln_cell = f"<td class='vuln'>{vulns}</td>" if vulns else "<td>None</td>"
        rows += (
            f"<tr><td>{safe_h}</td><td>{it.get('port')}/tcp</td>"
            f"<td>{safe_srv}</td><td>{safe_info}</td>{vuln_cell}</tr>\n"
        )
    
    html_doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Titan Security Report</title>
<style>
  body  {{ font-family: Arial, sans-serif; background: #0f0f1b; color: #fff; margin: 30px; }}
  h1    {{ color: #00ffcc; border-bottom: 2px solid #333; padding-bottom: 10px; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 20px; background: #1a1a2e; }}
  th, td {{ border: 1px solid #333; padding: 12px; text-align: left; }}
  th    {{ background: #16213e; color: #00ffcc; }}
  tr:nth-child(even) {{ background: #131324; }}
  .vuln {{ color: #ff4d4d; font-weight: bold; }}
</style>
</head><body>
<h1>⚡ OmniScan Titan — Intelligence Report</h1>
<p><strong>Date:</strong> {html.escape(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</p>
<table>
  <tr><th>Host</th><th>Port</th><th>Service</th><th>Banner / Intelligence</th><th>Vulnerabilities</th></tr>
{rows}
</table></body></html>"""
    
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_doc)
    console.print(f"[+] Exported HTML Report -> [bold green]{path}[/bold green]")
