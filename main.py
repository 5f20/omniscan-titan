import sys
import asyncio
import argparse
from datetime import datetime
from rich.console import Console
from rich.panel import Panel

from scanner import OmniScanTitan
from utils import setup_signal_handlers
from exporter import export_results

console = Console()

async def main_async() -> None:
    parser = argparse.ArgumentParser(
        description="OmniScan Titan ⚡ v2.0 (by 5f20) — Advanced Enterprise Recon Framework",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    tg = parser.add_mutually_exclusive_group(required=True)
    tg.add_argument("-t", "--target", help="Target IP, hostname, or CIDR (e.g., 10.0.0.0/24)")
    tg.add_argument("-iL", "--input-file", help="File containing one target per line")

    parser.add_argument("-p", "--ports", required=True, help="Ports: '80,443', '1-1000', 'top', or 'all'")
    parser.add_argument("-m", "--mode", choices=["async", "nmap", "hybrid"], default="hybrid")
    parser.add_argument("--nmap-args", default="-sV -sC -Pn -T4 --version-light", help="Allowlisted nmap flags only")
    parser.add_argument("-w", "--workers", type=int, default=2500, help="Initial FD Concurrency Limit")
    parser.add_argument("--timeout", type=float, default=1.5, help="Socket timeout")
    
    # Advanced / OPSEC Features
    parser.add_argument("--udp", action="store_true", help="Enable UDP scanning with deep payloads")
    parser.add_argument("--doh", action="store_true", help="Use DNS over HTTPS (Cloudflare/Google) to prevent ISP snooping")
    parser.add_argument("--opsec", action="store_true", help="Enable Stealth Mode (Jitter, UA rotation, AIMD limits)")
    parser.add_argument("--proxy", type=str, help="SOCKS5 Proxy (e.g., socks5://127.0.0.1:9050) for HTTP analyzers")

    # Exports
    parser.add_argument("-oJ", "--out-json")
    parser.add_argument("-oC", "--out-csv")
    parser.add_argument("-oM", "--out-md")
    parser.add_argument("-oH", "--out-html")
    parser.add_argument("-oS", "--out-sql")

    args = parser.parse_args()

    # uvloop inject for maximum I/O performance on Unix environments
    if sys.platform != "win32":
        try:
            import uvloop
            uvloop.install()
        except ImportError:
            pass

    console.print(Panel.fit(
        "[bold cyan]OmniScan Titan ⚡ v2.0 (by 5f20)[/bold cyan]\n"
        "[dim]3-Phase Adaptive Reconnaissance Framework (UDP/TCP/DoH/Nmap)[/dim]",
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

        # Only process exports if the scan wasn't aborted early
        if not scanner.shutdown_event.is_set():
            scanner.display_results()
            export_results(scanner.results, args)

    except asyncio.CancelledError:
        console.print("\n[dim yellow][!] Scan aborted by user. Exiting cleanly...[/dim yellow]")
    except Exception as exc:
        console.print(f"\n[bold red][!] Fatal Error: {exc}[/bold red]")
    finally:
        # Failsafe: Destroy global HTTP session pool exactly ONCE
        await scanner.close_session()
        
        duration = datetime.now() - start_time
        console.print(f"\n[*] Execution Time: [bold yellow]{duration.total_seconds():.2f}s[/bold yellow].")

if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        # Fallback catch in case event loop was totally blocked
        pass
