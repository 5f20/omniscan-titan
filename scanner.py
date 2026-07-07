import asyncio
import os
import sys
import re
import random
import tempfile
import shutil
import concurrent.futures
import ipaddress
import socket
import shlex
import aiohttp
from typing import AsyncGenerator, Dict, Any, Set, List, Optional, Tuple

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.tree import Tree
from rich.table import Table
from rich.live import Live
from rich.layout import Layout

from constants import PORT_SERVICES, WAF_SIGNATURES, USER_AGENTS, HEURISTICS, SAFE_NMAP_FLAGS, UDP_PAYLOADS, _SENTINEL
from utils import _TEMP_FILES_REGISTRY, optimize_os_limits
from token_bucket import TokenBucket
from conn_pool import ConnectionPool

console = Console()

try:
    import defusedxml.ElementTree as ET
except ImportError:
    sys.exit("[FATAL] defusedxml is required. Ensure 'pip install defusedxml' is run.")

class OmniScanTitan:
    def __init__(self, args) -> None:
        self.args = args
        self.max_workers = optimize_os_limits(args.workers)
        self.raw_targets = self._get_raw_targets(args.target, args.input_file)
        self.ports = self._parse_ports(args.ports)
        self.timeout = args.timeout
        self.nmap_args = self._validate_nmap_args(args.nmap_args)
        self.udp_enabled = getattr(args, 'udp', False)
        self.opsec = getattr(args, 'opsec', False)

        # Network Traffic Controllers
        self.global_bucket = TokenBucket(rate=getattr(args, 'global_rate', 1000.0), capacity=getattr(args, 'global_burst', 2000))
        self.per_host_buckets: Dict[str, TokenBucket] = {}
        self.pool = ConnectionPool(max_global=args.workers, per_host=10, conn_ttl=60.0)
        
        # Subprocess Executor for CPU-bound tasks
        cpu_cores = max(1, (os.cpu_count() or 4) - 1)
        self.process_pool = concurrent.futures.ProcessPoolExecutor(max_workers=cpu_cores)

        self.results: Dict[str, Dict[int, Dict[str, Any]]] = {}
        self.live_discoveries: List[str] = []
        self.stats: Dict[str, Any] = {"hosts_up": set(), "ports_open": 0, "vulns_found": 0}

        self.lock = asyncio.Lock()
        self.shutdown_event = asyncio.Event()
        self._dns_semaphore = asyncio.Semaphore(64)
        self.http_session: Optional[aiohttp.ClientSession] = None

    @staticmethod
    def _get_raw_targets(target_str: Optional[str], input_file: Optional[str]):
        found = False
        if target_str:
            found = True
            yield target_str
        if input_file and os.path.exists(input_file):
            with open(input_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        found = True
                        yield line
        if not found:
            sys.exit("[bold red][X] Error: No valid targets provided.[/bold red]")

    @staticmethod
    def _parse_ports(port_string: str) -> List[int]:
        if port_string.lower() == "top": 
            return list(PORT_SERVICES.keys())
        if port_string.lower() == "all": 
            return list(range(1, 65536))
            
        ports = set()
        for part in port_string.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    s, e = map(int, part.split("-"))
                    ports.update(range(s, e + 1))
                except ValueError: 
                    pass
            elif part.isdigit():
                ports.add(int(part))
        return sorted(list(ports))

    @staticmethod
    def _validate_nmap_args(raw_args: str) -> List[str]:
        tokens = shlex.split(raw_args)
        _SAFE_VALUE_RE = re.compile(r"^[A-Za-z0-9.\-_:]+$")
        rejected = [t for t in tokens if (t.startswith("-") and t not in SAFE_NMAP_FLAGS) or (not t.startswith("-") and not _SAFE_VALUE_RE.match(t))]
        if rejected:
            sys.exit(f"[bold red][!] Unsafe nmap token(s) rejected: {', '.join(rejected)}[/bold red]")
        return tokens

    async def _resolve_target(self, target: str) -> AsyncGenerator[str, None]:
        loop = asyncio.get_running_loop()
        try:
            if "/" in target:
                for ip in ipaddress.IPv4Network(target, strict=False): 
                    yield str(ip)
                return
            ipaddress.IPv4Address(target)
            yield target
            return
        except ValueError: 
            pass

        async with self._dns_semaphore:
            try:
                info = await asyncio.wait_for(loop.getaddrinfo(target, None, family=socket.AF_INET), timeout=5.0)
                yield info[0][4][0]
            except Exception: 
                pass

    async def _analyze_http_fast(self, host: str, port: int, use_ssl: bool) -> str:
        """Asynchronous HTTP application-layer analysis."""
        protocol = "https" if use_ssl else "http"
        url = f"{protocol}://{host}:{port}/"
        info_tags = []

        try:
            async with self.http_session.get(url, allow_redirects=False, headers={"User-Agent": random.choice(USER_AGENTS)}) as resp:
                server = resp.headers.get("Server", "")
                if server:
                    info_tags.append(f"Srv: {server[:20]}")
                    if any(w in server.lower() for w in WAF_SIGNATURES): 
                        info_tags.append("🛡️ WAF Detected")
                if "X-Powered-By" in resp.headers:
                    info_tags.append(f"Tech: {resp.headers['X-Powered-By'][:20]}")
                    
                text = await resp.text()
                title_match = re.search(r"(?i)<title>(.*?)</title>", text, re.DOTALL)
                if title_match:
                    info_tags.append(f"Title: '{' '.join(title_match.group(1).split())[:45]}'")
        except Exception:
            return PORT_SERVICES.get(port, ("Unknown", "", ""))[0]

        return " | ".join(info_tags) if info_tags else "HTTP Open"

    async def _probe_udp(self, host: str, port: int) -> Optional[str]:
        """Deep payload injection for stateless UDP verification."""
        payload = UDP_PAYLOADS.get(port)
        if not payload: 
            return None

        loop = asyncio.get_running_loop()
        class UDPProtocol(asyncio.DatagramProtocol):
            def __init__(self): 
                self.response = asyncio.Future()
            def datagram_received(self, data, addr):
                if not self.response.done(): self.response.set_result(data)
            def error_received(self, exc):
                if not self.response.done(): self.response.set_exception(exc)

        try:
            transport, protocol = await asyncio.wait_for(
                loop.create_datagram_endpoint(lambda: UDPProtocol(), remote_addr=(host, port)), timeout=self.timeout
            )
            transport.sendto(payload)
            data = await asyncio.wait_for(protocol.response, timeout=self.timeout)
            transport.close()
            return f"UDP Reply: {len(data)} bytes"
        except Exception:
            return None

    async def _smart_banner_grab(self, host: str, port: int) -> str:
        """Determines context and routing for target interrogation."""
        srv_name = PORT_SERVICES.get(port, ("Unknown", "white", "unknown"))[0]
        use_ssl = port in (443, 8443) or "https" in srv_name.lower()
        
        if host not in self.per_host_buckets:
            self.per_host_buckets[host] = TokenBucket(rate=50.0, capacity=200)
        
        ok_global = await self.global_bucket.consume(1, timeout=2.0)
        ok_host = await self.per_host_buckets[host].consume(1, timeout=2.0)
        if not ok_global or not ok_host: 
            return srv_name

        if port in (80, 8080) or "http" in srv_name.lower() or use_ssl:
            return await self._analyze_http_fast(host, port, use_ssl)

        conn = None
        try:
            conn = await self.pool.acquire(host, port, use_ssl, timeout=self.timeout + 2)
            writer, reader = conn.writer, conn.reader
            writer.write(b"\r\n")
            await writer.drain()
            
            data = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            if data:
                banner = "".join(c if 32 <= ord(c) < 127 else " " for c in data.decode("utf-8", errors="replace")).strip()[:160]
                if getattr(conn, 'untrusted_ssl', False):
                    banner = f"[MitM RISK / Untrusted SSL] {banner}"
                return banner
        except Exception:
            pass
        finally:
            if conn: 
                await self.pool.release(host, port, use_ssl, conn, keep_alive=True)
                
        return srv_name

    async def _worker(self, queue: asyncio.Queue, progress: Progress, task_id: int) -> None:
        while not self.shutdown_event.is_set():
            item = await queue.get()
            try:
                if item is _SENTINEL or self.shutdown_event.is_set(): 
                    break
                host, port, proto = item
                
                if self.opsec:
                    await asyncio.sleep(random.uniform(0.1, 0.5))
                    
                banner = None
                if proto == "tcp": 
                    banner = await self._smart_banner_grab(host, port)
                elif proto == "udp": 
                    banner = await self._probe_udp(host, port)
                
                if not banner: 
                    continue
                if proto == "udp": 
                    banner = f"[UDP] {banner}"

                srv_name, color, _ = PORT_SERVICES.get(port, ("Unknown", "white", "unknown"))
                vulns = [name for regex, name in HEURISTICS.items() if re.search(regex, banner)]

                async with self.lock:
                    if host not in self.results: 
                        self.results[host] = {}
                    if port not in self.results[host]:
                        self.results[host][port] = {"state": "open", "service": srv_name, "info": banner, "vulns": vulns}
                        self.stats["ports_open"] += 1
                        self.stats["hosts_up"].add(host)
                        self.stats["vulns_found"] += len(vulns)
                    else:
                        self.results[host][port]["info"] += f" | {banner}"

                    vuln_str = f" [bold red]🚨 {', '.join(vulns)}[/bold red]" if vulns else ""
                    msg = f"[[bold green]+[/bold green]] {host}:{port} -> [{color}]{srv_name}[/{color}] ({banner}){vuln_str}"
                    self.live_discoveries.append(msg)
                    if len(self.live_discoveries) > 8: 
                        self.live_discoveries.pop(0)

            except Exception: 
                pass
            finally:
                progress.advance(task_id)
                queue.task_done()

    async def _feeder(self, queue: asyncio.Queue, progress: Progress, task_id: int) -> None:
        try:
            total_items = 0
            for t in self.raw_targets:
                async for ip in self._resolve_target(t): 
                    for port in self.ports:
                        if self.shutdown_event.is_set(): break
                        await queue.put((ip, port, "tcp"))
                        total_items += 1
                    if self.udp_enabled:
                        for udp_port in UDP_PAYLOADS.keys():
                            if self.shutdown_event.is_set(): break
                            await queue.put((ip, udp_port, "udp"))
                            total_items += 1
                    progress.update(task_id, total=total_items)
        finally:
            for _ in range(self.max_workers): 
                await queue.put(_SENTINEL)

    async def engine_async_socket(self) -> None:
        console.print(f"\n[*] Starting [bold blue]Titan Asynchronous Matrix[/bold blue] (Concurrency: {self.max_workers})")
        queue: asyncio.Queue = asyncio.Queue(maxsize=self.max_workers * 2)

        # Global connection handling for HTTP traffic
        connector = aiohttp.TCPConnector(ssl=False, limit=self.max_workers, limit_per_host=self.args.per_host_conn)
        self.http_session = aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=self.timeout + 1.0))

        progress = Progress(
            SpinnerColumn("dots2"), TextColumn("[bold blue]{task.description}"),
            BarColumn(complete_style="cyan", finished_style="green"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TimeElapsedColumn()
        )
        task_id = progress.add_task("Sweeping...", total=0)
        feeder_task = asyncio.create_task(self._feeder(queue, progress, task_id))
        workers = [asyncio.create_task(self._worker(queue, progress, task_id)) for _ in range(self.max_workers)]

        async def update_ui():
            with Live(refresh_per_second=10) as live:
                while not self.shutdown_event.is_set() and (not feeder_task.done() or not queue.empty() or not all(w.done() for w in workers)):
                    async with self.lock:
                        content = "\n".join(self.live_discoveries) if self.live_discoveries else "[dim]Scanning digital footprint...[/dim]"
                        stats = f"[green]Hosts:[/green] {len(self.stats['hosts_up'])} | [cyan]Ports:[/cyan] {self.stats['ports_open']} | [red]Vulns:[/red] {self.stats['vulns_found']}"
                    
                    layout = Layout()
                    layout.split_column(
                        Layout(Panel(content, title="⚡ Live Telemetry", border_style="cyan"), ratio=3),
                        Layout(Panel(stats, border_style="green"), ratio=1),
                        Layout(progress, ratio=1)
                    )
                    live.update(layout)
                    await asyncio.sleep(0.1)

        ui_task = asyncio.create_task(update_ui())

        while not feeder_task.done() or not queue.empty() or not all(w.done() for w in workers):
            if self.shutdown_event.is_set():
                feeder_task.cancel()
                for w in workers: w.cancel()
                break
            await asyncio.sleep(0.1)

        await queue.join()
        ui_task.cancel()
        
        if self.http_session:
            await self.http_session.close()

    @staticmethod
    def _parse_nmap_xml(xml_path: str) -> Dict[str, Dict[int, Dict[str, Any]]]:
        """Iterative XML Parsing executed independently in ProcessPoolExecutor."""
        updates = {}
        try:
            if not os.path.exists(xml_path) or os.path.getsize(xml_path) == 0: 
                return updates
            for event, elem in ET.iterparse(xml_path, events=("end",)):
                if elem.tag == "host":
                    addr_elem = elem.find("address")
                    if addr_elem is None: 
                        continue
                    addr = addr_elem.get("addr")
                    ports = {}
                    for port_elem in elem.findall(".//port"):
                        state = port_elem.find("state")
                        if state is None or state.get("state") not in ("open", "open|filtered"): 
                            continue
                        port_id = int(port_elem.get("portid", 0))
                        srv = port_elem.find("service")
                        banner = f"{srv.get('product', '')} {srv.get('version', '')}".strip() if srv is not None else ""
                        ports[port_id] = {"service": srv.get("name", "unknown").upper() if srv is not None else "UNKNOWN", "nmap_banner": banner}
                    if ports: 
                        updates[addr] = ports
                    elem.clear()
        except Exception: 
            pass
        return updates

    async def engine_nmap_subprocess(self, specific_targets=None) -> None:
        if not shutil.which("nmap"): 
            return
        if self.shutdown_event.is_set(): 
            return
        console.print("\n[*] Initiating [bold red]Nmap Deep Packet Inspection Engine[/bold red]")
        
        nmap_tasks = []
        if specific_targets:
            port_map = {}
            nmap_tasks = []
        if specific_targets:
            port_map = {}
            shm_dir = "/dev/shm" if os.path.isdir("/dev/shm") else None
            for host, ports in specific_targets.items():
                if ports: 
                    port_map.setdefault(tuple(sorted(ports)), []).append(host)
            for tup_ports, hosts in port_map.items():
                fd, path = tempfile.mkstemp(text=True, dir=shm_dir)
                with os.fdopen(fd, "w") as f: 
                    f.write("\n".join(hosts))
                xml_fd, xml_path = tempfile.mkstemp(suffix=".xml", text=True, dir=shm_dir)
                os.close(xml_fd)
                cmd = ["nmap"] + self.nmap_args + ["-p", ",".join(map(str, tup_ports[:200])), "-oX", xml_path, "-iL", path]
                nmap_tasks.append((cmd, xml_path, path))

        nmap_semaphore = asyncio.Semaphore(10)
        async def _run(cmd, xml_path, target_list):
            async with nmap_semaphore:
                proc = None
                try:
                    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
                    await proc.communicate()
                    
                    loop = asyncio.get_running_loop()
                    updates = await loop.run_in_executor(self.process_pool, self._parse_nmap_xml, xml_path)
                    # Remove the duplicate block and fix indentation inside _run()
        if updates:
            async with self.lock:
                for addr, p_dict in updates.items():
                    if addr not in self.results: 
                        self.results[addr] = {}
                    for pid, nd in p_dict.items():
                        existing = self.results[addr].get(pid, {})
                        e_banner = existing.get("info", "")
                        new_banner = f"{e_banner} ➕ Nmap: {nd['nmap_banner']}" if e_banner else nd['nmap_banner']
                        self.results[addr][pid] = {"state": "open", "service": nd["service"], "info": new_banner, "vulns": existing.get("vulns", [])}
                        
                finally:
                    if proc and proc.returncode is None:
                        try:
                            proc.kill()
                            await proc.wait()
                        except ProcessLookupError:
                            pass
                    if os.path.exists(xml_path): os.remove(xml_path)
                    if os.path.exists(target_list): os.remove(target_list)

        with Progress(SpinnerColumn("bouncingBall"), TextColumn("[red]Executing Nmap Tasks..."), TimeElapsedColumn()) as p:
            task = p.add_task("Nmap", total=len(nmap_tasks))
            await asyncio.gather(*[_run(c, x, t) for c, x, t in nmap_tasks])
            p.advance(task)

    async def engine_hybrid(self) -> None:
        await self.engine_async_socket()
        open_targets = {h: list(p.keys()) for h, p in self.results.items() if p}
        if open_targets:
            await self.engine_nmap_subprocess(open_targets)

    def display_results(self) -> None:
        console.print("\n")
        has_results = False
        for host, ports in sorted(self.results.items()):
            if not ports: 
                continue
            has_results = True
            root_tree = Tree(f"🌐 [bold white]Host:[/bold white] [bold cyan]{host}[/bold cyan]")
            table = Table(show_header=True, header_style="bold magenta", box=None, padding=(0, 2))
            table.add_column("Port")
            table.add_column("State")
            table.add_column("Service")
            table.add_column("Vulnerability / App Info")

            for p in sorted(ports.keys()):
                d = ports[p]
                _, color, _ = PORT_SERVICES.get(p, ("Unknown", "white", "unknown"))
                safe_info = str(d["info"]).replace("[", r"\[").replace("]", r"\]")
                if d.get("vulns"): 
                    safe_info = f"[bold red]🚨 VULN: {', '.join(d['vulns'])}[/bold red] | " + safe_info
                table.add_row(f"[{color}]{p}/tcp[/{color}]", "[bold green]OPEN[/bold green]", f"[{color}]{d['service']}[/{color}]", f"[dim white]{safe_info}[/dim white]")
            
            root_tree.add(table)
            console.print(Panel(root_tree, border_style="cyan"))

        if not has_results: 
            console.print("[bold yellow][!] Scan complete. No open ports discovered.[/bold yellow]")
