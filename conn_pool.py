import asyncio
import ssl
import time
from typing import Dict, Tuple

class PooledConnection:
    """Wrapper for raw asyncio stream connections tracking lifecycle metrics."""
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, created_at: float):
        self.reader = reader
        self.writer = writer
        self.created_at = created_at
        self.in_use = False
        self.untrusted_ssl = False

    async def close(self):
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass

class ConnectionPool:
    """
    Manages raw TCP socket recycling to prevent OS ephemeral port exhaustion.
    Enforces per-host semaphores and global connection caps.
    """
    def __init__(self, max_global: int = 2000, per_host: int = 10, conn_ttl: float = 60.0):
        self._max_global = max_global
        self._per_host = per_host
        self._conn_ttl = conn_ttl
        self._pools: Dict[Tuple[str, int, bool], asyncio.Queue] = {}
        self._host_semaphores: Dict[str, asyncio.Semaphore] = {}
        self._global_semaphore = asyncio.Semaphore(max_global)
        self._lock = asyncio.Lock()

    async def acquire(self, host: str, port: int, use_ssl: bool, timeout: float = 10.0) -> PooledConnection:
        key = (host, port, use_ssl)
        async with self._lock:
            if key not in self._pools:
                self._pools[key] = asyncio.Queue()
            if host not in self._host_semaphores:
                self._host_semaphores[host] = asyncio.Semaphore(self._per_host)
            
            pool = self._pools[key]
            host_sem = self._host_semaphores[host]

        await asyncio.wait_for(self._global_semaphore.acquire(), timeout=timeout)
        await asyncio.wait_for(host_sem.acquire(), timeout=timeout)

        # Attempt to reuse an existing connection
        try:
            while not pool.empty():
                conn: PooledConnection = pool.get_nowait()
                if time.monotonic() - conn.created_at > self._conn_ttl:
                    await conn.close()
                    continue
                conn.in_use = True
                return conn
        except asyncio.QueueEmpty:
            pass

        # Establish a new connection if no valid recycled connections exist
        try:
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.open_connection(host, port, ssl=ctx)
            else:
                reader, writer = await asyncio.open_connection(host, port)
            
            conn = PooledConnection(reader, writer, time.monotonic())
            conn.in_use = True
            return conn
        except Exception:
            self._global_semaphore.release()
            host_sem.release()
            raise

    async def release(self, host: str, port: int, use_ssl: bool, conn: PooledConnection, keep_alive: bool = True):
        key = (host, port, use_ssl)
        conn.in_use = False
        
        async with self._lock:
            pool = self._pools.get(key)
            host_sem = self._host_semaphores.get(host)
            
        if keep_alive and pool is not None and pool.qsize() < self._per_host:
            await pool.put(conn)
        else:
            await conn.close()
            
        self._global_semaphore.release()
        if host_sem:
            host_sem.release()
