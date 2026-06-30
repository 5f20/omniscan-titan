import asyncio
import os
import sys
import atexit
import signal
import threading
from typing import List, Any
from rich.console import Console

console = Console()
_TEMP_FILES_REGISTRY: List[str] = []

def _cleanup_temp_files() -> None:
    for path in _TEMP_FILES_REGISTRY:
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass

atexit.register(_cleanup_temp_files)

def optimize_os_limits(requested_workers: int) -> int:
    """Aggressively maximizes OS file descriptors."""
    if os.name != "nt":
        try:
            import resource
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            target_limit = min(hard if hard > 0 else 1048576, 1048576)
            if soft < target_limit:
                resource.setrlimit(resource.RLIMIT_NOFILE, (target_limit, hard))
            return min(requested_workers, target_limit - 100)
        except Exception as e:
            console.print(f"[dim yellow][!] Limit optimization failed: {e}[/dim yellow]")
            return min(requested_workers, 1024)
    return min(requested_workers, 1000) # Windows fallback

def setup_signal_handlers(scanner: Any) -> None:
    if threading.current_thread() is not threading.main_thread():
        return

    def handle_sigint(sig: int, frame: Any) -> None:
        if not scanner.shutdown_event.is_set():
            console.print("\n[bold red]🚨 OPSEC Halt Initiated — Saving Intel...[/bold red]")
            loop = asyncio.get_running_loop()
            loop.call_soon_threadsafe(scanner.shutdown_event.set)

    signal.signal(signal.SIGINT, handle_sigint)
    if sys.platform != "win32":
        signal.signal(signal.SIGTERM, handle_sigint)
