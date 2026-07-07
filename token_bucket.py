import asyncio
import time
from typing import Optional

class TokenBucket:
    """
    Implements a strict token bucket algorithm for network rate limiting.
    Ensures outbound packet rates mathematically adhere to defined thresholds.
    """
    def __init__(self, rate: float, capacity: int) -> None:
        self._rate = float(rate)
        self._capacity = int(capacity)
        self._tokens = float(capacity)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def consume(self, tokens: int = 1, timeout: Optional[float] = None) -> bool:
        if tokens > self._capacity:
            return False # Prevents infinite loop trap
            
        deadline = None if timeout is None else time.monotonic() + timeout
        
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self._last
                
                if elapsed > 0:
                    self._tokens = min(float(self._capacity), self._tokens + elapsed * self._rate)
                    self._last = now
                    
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return True
                    
                if deadline is not None and now >= deadline:
                    return False
                    
                need = tokens - self._tokens
                sleep_time = max(need / self._rate, 0.001)
                
            # ✅ SLEEP MUST BE OUTSIDE THE LOCK
            await asyncio.sleep(min(sleep_time, 1.0))
