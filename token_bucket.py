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
        """
        Attempts to consume a specific number of tokens.
        Blocks asynchronously until tokens are available or the timeout is reached.
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._last
                
                if elapsed > 0:
                    self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
                    self._last = now
                    
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return True
                    
                if deadline is not None and now >= deadline:
                    return False
                    
                need = tokens - self._tokens
                sleep_time = max(need / self._rate, 0.001)
                await asyncio.sleep(min(sleep_time, 1.0))
