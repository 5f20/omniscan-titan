import sys
import asyncio
import argparse
import platform
from datetime import datetime
from rich.console import Console
from rich.panel import Panel

from scanner import OmniScanTitan
from exporter import export_json_stream, export_csv_stream, export_sqlite, export_html

console = Console()

def setup_signal_handlers(scanner):
    """Hooks into OS level interrupt signals for graceful degradation."""
    try:
        loop = asyncio.get_running_loop()
        def handle():
            scanner.shutdown_event.set()
            console.print("\n[bold red]🚨 Halt Initiated... Canceling tasks.[/bold red]")
            current_task = asyncio.current_task(loop)
            for task in asyncio.all_tasks(loop):
                if task is not current_task and not task.done():
                    task.cancel()
        if sys.platform != "win32":
            import signal
            loop.add_signal_handler(signal.SIGINT, handle)
            loop.add_signal_handler(signal.SIGTERM, handle)
    except Exception:
        pass

async def main_async() -> None:
    parser = argparse.ArgumentParser(description="OmniScan Titan ⚡ Network Intelligence Framework")
    parser.add_argument("-t", "--target", help="Target IP/CIDR", required=True)
    parser.add_argument("-iL", "--input-file", help="File of targets")
    parser.add_argument("-p", "--ports", default="top", help="Ports (e.g. 80,443 or top)")
    parser.add_argument("-m", "--mode", choices=["async", "hybrid"], default="hybrid")
    parser.add_argument("-w", "--workers", type=int, default=2000, help="Async FD Limit")
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--udp", action="store_true", help="Enable UDP probe payloads")
    parser.add_argument("--opsec", action="store_true", help="Enable adaptive scan jitter")
    parser.add_argument("--nmap-args", default="-sV -Pn -T4")
    
    # Mathematical Constraints
    parser.add_argument("--global-rate", type=float, default=1500.0)
    parser.add_argument("--global-burst", type=int, default=3000)
    parser.add_argument("--per-host-conn", type=int, default=20)
    parser.add_argument("--max-connections", type=int, default=2500)
    parser.add_argument("--conn-ttl", type=float, default=30.0)
    
    # Exfiltration Handling
    parser.add_argument("-oJ", "--out-json")
    parser.add_argument("-oC", "--out-csv")
    parser.add_argument("-oS", "--out-sql")
    parser.add_argument("-oH", "--out-html")

    args = parser.parse_args()

    if sys.platform != "win32":
        try:
            import uvloop
            uvloop.install()
        except ImportError: 
            pass

    console.print(Panel.fit(
        "[bold cyan]OmniScan Titan ⚡[/bold cyan]\n"
        "[dim]High-Performance Async/UDP/TCP Recon Engine[/dim]", 
        border_style="cyan"
    ))
    
    scanner = OmniScanTitan(args)
    setup_signal_handlers(scanner)
    start = datetime.now()

    try:
        if args.mode == "async": 
            await scanner.engine_async_socket()
        else: 
            await scanner.engine_hybrid()

        # Generates a flat stream for O(1) memory writing
        def iter_results():
            for host, ports in scanner.results.items():
                for port, d in ports.items():
                    yield {
                        "host": host, 
                        "port": port, 
                        "state": d.get("state"), 
                        "service": d.get("service"), 
                        "info": d.get("info"), 
                        "vulns": d.get("vulns", [])
                    }

        if args.out_json: 
            await export_json_stream(args.out_json, iter_results())
        if args.out_csv: 
            await export_csv_stream(args.out_csv, iter_results())
        if args.out_sql: 
            await export_sqlite(args.out_sql, iter_results())
        if args.out_html: 
            export_html(args.out_html, iter_results()) 

    except asyncio.CancelledError:
        pass
    finally:
        # Ensures child processing resources are cleanly destroyed
        scanner.process_pool.shutdown(wait=False)
        console.print(f"\n[*] Execution Time: [bold yellow]{(datetime.now() - start).total_seconds():.2f}s[/bold yellow]")

if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        pass
