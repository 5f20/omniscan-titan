import sys
import asyncio
import argparse
from datetime import datetime

from rich.console import Console
from rich.panel import Panel

# Import our custom components
from scanner import OmniScanTitan
from utils import setup_signal_handlers
from exporter import export_results

console = Console()

async def main_async() -> None:
    parser = argparse.ArgumentParser(
        description="OmniScan Titan ⚡ v1.0 (by 5f20) — Enterprise Network & App-Layer Recon",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    tg = parser.add_mutually_exclusive_group(required=True)
    tg.add_argument("-t", "--target", help="Target IP, hostname, or CIDR (e.g., 10.0.0.0/24)")
    tg.add_argument("-iL", "--input-file", help="File containing one target per line")

    parser.add_argument("-p", "--ports", required=True, help="Ports: '80,443', '1-1000', 'top', or 'all'")
    parser.add_argument("-m", "--mode", choices=["async", "nmap", "hybrid"], default="hybrid")
    parser.add_argument("--nmap-args", default="-sV -sC -Pn -T4 --version-light", help="Allowlisted nmap flags only")
    parser.add_argument("-w", "--workers", type=int, default=1000)
    parser.add_argument("--timeout", type=float, default=1.5)
    
    # Export arguments
    parser.add_argument("-oJ", "--out-json")
    parser.add_argument("-oC", "--out-csv")
    parser.add_argument("-oM", "--out-md")
    parser.add_argument("-oH", "--out-html")
    parser.add_argument("-oS", "--out-sql")

    args = parser.parse_args()

    console.print(Panel.fit(
        "[bold cyan]OmniScan Titan ⚡ v1.0 (by 5f20)[/bold cyan]\n"
        "[dim]Enterprise Asynchronous Network Intelligence Framework[/dim]",
        border_style="cyan",
    ))

    scanner = OmniScanTitan(args)
    setup_signal_handlers(scanner)
    start_time = datetime.now()

    try:
        if args.mode == "async":
            await scanner.engine_async_socket()
        elif args.mode == "nmap":
            await scanner.engine_nmap_subprocess()
        elif args.mode == "hybrid":
            await scanner.engine_hybrid()

        # Display and export the gathered data
        scanner.display_results()
        export_results(scanner.results, args)

    except asyncio.CancelledError:
        pass
    except Exception as exc:
        console.print(f"\n[bold red][!] Fatal Error: {exc}[/bold red]")
    finally:
        duration = datetime.now() - start_time
        console.print(f"\n[*] Execution Time: [bold yellow]{duration.total_seconds():.2f}s[/bold yellow].")


if __name__ == "__main__":
    if sys.platform == "win32":
        # Windows Proactor Event Loop fix for Subprocess calls
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        pass
