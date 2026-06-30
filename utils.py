import os
import sys
import atexit
import signal
import asyncio
from typing import List, Any
from rich.console import Console

console = Console()

# Kept for backward compatibility or future global tasks.
# Phase 1 now uses atomic tempfile.TemporaryDirectory() for Nmap.
_TEMP_FILES_REGISTRY: List[str] = []

def _cleanup_temp_files() -> None:
    """Fallback cleanup for any orphaned temporary files."""
    for path in _TEMP_FILES_REGISTRY:
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass

atexit.register(_cleanup_temp_files)

def optimize_os_limits(requested_workers: int) -> int:
    """Aggressively maximizes OS file descriptors for peak concurrent performance."""
    if os.name != "nt":
        try:
            import resource
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            
            # Maximize File Descriptors
            target_limit = min(hard if hard > 0 else 1048576, 1048576)
            if soft < target_limit:
                resource.setrlimit(resource.RLIMIT_NOFILE, (target_limit, hard))
                
            # Buffer of 100 FDs reserved for OS/Python internals
            return min(requested_workers, target_limit - 100)
        except Exception as e:
            console.print(f"[dim yellow][!] Limit optimization failed: {e}[/dim yellow]")
            return min(requested_workers, 1024)
            
    # Windows fallback
    return min(requested_workers, 1000) 

def setup_signal_handlers(scanner: Any) -> None:
    """Binds OS interrupt signals directly to the asyncio event loop."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return

    def handle_sigint() -> None:
        if not scanner.shutdown_event.is_set():
            console.print("\n[bold red]🚨 OPSEC Halt Initiated — Safely closing connections...[/bold red]")
            scanner.shutdown_event.set()

    # Native, non-blocking asyncio signal handling for Unix
    if sys.platform != "win32":
        try:
            loop.add_signal_handler(signal.SIGINT, handle_sigint)
            loop.add_signal_handler(signal.SIGTERM, handle_sigint)
        except NotImplementedError:
            # Fallback for alternative event loops
            signal.signal(signal.SIGINT, lambda sig, frame: loop.call_soon_threadsafe(handle_sigint))
    else:
        # Windows ProactorEventLoop does not support add_signal_handler natively
        signal.signal(signal.SIGINT, lambda sig, frame: loop.call_soon_threadsafe(handle_sigint))
        signal.signal(signal.SIGTERM, lambda sig, frame: loop.call_soon_threadsafe(handle_sigint))
