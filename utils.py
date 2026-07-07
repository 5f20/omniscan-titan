import os
import atexit
from rich.console import Console

console = Console()

# Registry specifically tracking transient processes/files
_TEMP_FILES_REGISTRY = []

def _cleanup_temp_files():
    """Fallback cleanup for orphaned OS resources."""
    for path in _TEMP_FILES_REGISTRY:
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass

atexit.register(_cleanup_temp_files)

def optimize_os_limits(requested_workers: int) -> int:
    """Modifies local kernel constraints to allow peak concurrent file descriptors."""
    if os.name != "nt":
        try:
            import resource
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            target_limit = min(hard if hard > 0 else 1048576, 1048576)
            if soft < target_limit:
                resource.setrlimit(resource.RLIMIT_NOFILE, (target_limit, hard))
            
            # Subtracted boundary preserves FDs for internal OS tasks
            return min(requested_workers, max(1, target_limit - 200))
        except Exception as e:
            console.print(f"[dim yellow][!] Limit optimization failed: {e}[/dim yellow]")
            return min(requested_workers, 1024)
            
    # Windows native boundary
    return min(requested_workers, 1000)
