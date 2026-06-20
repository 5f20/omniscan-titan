import asyncio
import os
import atexit
import signal
import threading
from typing import List, Any
from rich.console import Console

console = Console()

# Global list of temp paths so atexit can clean up on unexpected exit.
_TEMP_FILES_REGISTRY: List[str] = []

def _cleanup_temp_files() -> None:
    for path in _TEMP_FILES_REGISTRY:
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass

atexit.register(_cleanup_temp_files)

def setup_signal_handlers(scanner: Any) -> None:
    if threading.current_thread() is not threading.main_thread():
        console.print(
            "[yellow][!] Signal handler skipped — not running in main thread. "
            "Send SIGINT manually if needed.[/yellow]"
        )
        return

    def handle_sigint(sig: int, frame: Any) -> None:
        if not scanner.shutdown_event.is_set():
            console.print(
                "\n[bold red]🚨 Interrupt detected — "
                "gracefully halting and saving data...[/bold red]"
            )
            loop = asyncio.get_running_loop()
            loop.call_soon_threadsafe(scanner.shutdown_event.set)

    signal.signal(signal.SIGINT, handle_sigint)
