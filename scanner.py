import asyncio
import argparse
import ipaddress
import os
import sys
import ssl
import re
import socket
import shlex
import tempfile
import threading
import shutil
import random
import aiohttp
from typing import AsyncGenerator, Dict, Any, Set, List, Optional, Tuple

from constants import PORT_SERVICES, WAF_SIGNATURES, USER_AGENTS, HEURISTICS, SAFE_NMAP_FLAGS, UDP_PAYLOADS, DOH_PROVIDERS, _SENTINEL
from utils import _TEMP_FILES_REGISTRY, optimize_os_limits

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.tree import Tree
from rich.table import Table

console = Console()

try:
    import defusedxml.ElementTree as ET
except ImportError:
    sys.exit("[FATAL] defusedxml is required for secure XML parsing. Run: pip install defusedxml")

class AdaptiveRateLimiter:
    """Dynamically scales active socket connections to prevent network drops."""
    def __init__(self, initial_limit: int):
        self.limit = initial_limit
        self.semaphore = asyncio.Semaphore(initial_limit)
        self.timeout_count = 0
        self.success_count = 0

    def record_timeout(self):
        self.timeout_count += 1
        if self.timeout_count > 50:
            self.timeout_count = 0
            # AIMD: Multiplicative Decrease
            if self.limit > 100:
                self.limit = int(self.limit * 0.8)

    def record_success(self):
        self.success_count += 1
        if self.success_count > 100:
            self.success_count = 0
            # AIMD: Additive Increase
            self.limit += 50

class UDPProbeProtocol(asyncio.DatagramProtocol):
    def __init__(self, future: asyncio.Future):
        self.future = future

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        if not self.future.done():
            self.future.set_result((data, addr))

    def error_received(self, exc: Exception):
        if not self.future.done():
            self.future.set_exception(exc)

    def connection_lost(self, exc: Exception):
        if not self.future.done() and exc:
            self.future.set_exception(exc)

class OmniScanTitan:
    def __init__(self, args: argparse.Namespace) -> None:
        self.max_workers = optimize_os_limits(args.workers)
        self.raw_targets = self._get_raw_targets(args.target, args.input_file)
        self.ports = self._parse_ports(args.ports)
        self.mode = args.mode
        self.timeout = args.timeout
        self.nmap_args = self._validate_nmap_args(args.nmap_args)
        
        # OPSEC & Privacy Features
        self.doh = args.doh
        self.udp_mode = args.udp
        self.opsec = args.opsec
        self.proxy = args.proxy
        
        self.results: Dict[str, Dict[int, Dict[str, Any]]] = {}
        self.live_discoveries: List[str] = []
        self.stats: Dict[str, Any] = {"hosts_up": set(), "ports_open": 0, "vulns_found": 0}

        self.lock = asyncio.Lock()
        self.shutdown_event = asyncio.Event()
        self.rate_limiter = AdaptiveRateLimiter(self.max_workers)
        self._dns_cache: Dict[str, str] = {}

    @staticmethod
    def _get_raw_targets(target_str: Optional[str], input_file: Optional[str]) -> Set[str]:
        raw: Set[str] = set()
        if target_str: 
            raw.add(target_str)
        if input_file and os.path.exists(input_file):
            with open(input_file, "r", encoding="utf-8") as f:
                raw.update([line.strip() for line in f if line.strip() and not line.startswith("#")])
        if not raw:
            console.print("[bold red][X] Error: No valid targets provided.[/bold red]")
            sys.exit(1)
        return raw

    @staticmethod
    def _parse_ports(port_string: str) -> List[int]:
        if port_string.lower() == "top": return list(PORT_SERVICES.keys())
        if port_string.lower() == "all": return list(range(1, 65536))
        ports = set()
        for part in port_string.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    s, e = map(int, part.split("-", 1))
                    ports.update(p for p in range(s, e + 1) if 1 <= p <= 65535)
                except ValueError: pass
            elif part.isdigit() and 1 <= int(part) <= 65535:
                ports.add(int(part))
        return sorted(ports)

    @staticmethod
    def _validate_nmap_args(raw_args: str) -> List[str]:
        tokens = shlex.split(raw_args)
        rejected = [t for t in tokens if t.startswith("-") and t not in SAFE_NMAP_FLAGS]
        if rejected:
            console.print(f"[bold red][!] Unsafe nmap flags rejected: {', '.join(rejected)}[/bold red]")
            sys.exit(1)
        return tokens

    async def _resolve_doh(self, target: str) -> Optional[str]:
        """Privacy-first DNS over HTTPS resolution to bypass ISP interception."""
        if target in self._dns_cache: 
            return self._dns_cache[target]
            
        endpoint = random.choice(DOH_PROVIDERS)
        params = {"name": target, "type": "A"}
        headers = {"Accept": "application/dns-json"}
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                async with session.get(endpoint, params=params, headers=headers, timeout=self.timeout) as resp:
                    data = await resp.json()
                    if data.get("Status") == 0 and "Answer" in data:
                        ip = data["Answer"][0]["data"]
                        self._dns_cache[target] = ip
                        return ip
        except Exception:
            pass
        return None

    async def _resolve_target(self, target: str) -> AsyncGenerator[str, None]:
        if "/" in target:
            for ip in ipaddress.IPv4Network(target, strict=False):
                yield str(ip)
            return
        try:
            ipaddress.IPv4Address(target)
            yield target
            return
        except ipaddress.AddressValueError: 
            pass

        if self.doh:
            ip = await self._resolve_doh(target)
            if ip: 
                yield ip
                return

        # Standard Fallback
        try:
            info = await asyncio.wait_for(
                asyncio.get_running_loop().getaddrinfo(target, None, family=socket.AF_INET), timeout=5.0
            )
            yield info[0][4][0]
        except Exception: 
            pass

    async def _target_generator(self) -> AsyncGenerator[Tuple[str, int], None]:
        for t in self.raw_targets:
            async for ip in self._resolve_target(t):
                for port in self.ports:
                    if self.shutdown_event.is_set(): 
                        return
                    yield (ip, port)

    # =========================================================================
    # PHASE 1: HYPER-FAST RAW SOCKET DISCOVERY
    # =========================================================================
    async def _raw_tcp_check(self, host: str, port: int) -> bool:
        """C-level socket implementation to bypass Python's asyncio overhead."""
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        try:
            async with self.rate_limiter.semaphore:
                await asyncio.wait_for(loop.sock_connect(sock, (host, port)), timeout=self.timeout)
            self.rate_limiter.record_success()
            return True
        except asyncio.TimeoutError:
            self.rate_limiter.record_timeout()
            return False
        except Exception:
            return False
        finally:
            sock.close()

    async def _raw_udp_check(self, host: str, port: int) -> bool:
        loop = asyncio.get_running_loop()
        payload = UDP_PAYLOADS.get(port, b"\x00" * 12)
        fut = loop.create_future()
        transport = None
        try:
            async with self.rate_limiter.semaphore:
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: UDPProbeProtocol(fut), remote_addr=(host, port)
                )
                transport.sendto(payload)
                await asyncio.wait_for(fut, timeout=self.timeout)
            self.rate_limiter.record_success()
            return True
        except Exception:
            self.rate_limiter.record_timeout()
            return False
        finally:
            if transport: 
                transport.close()

    # =========================================================================
    # PHASE 2: INTELLIGENCE INTERROGATION
    # =========================================================================
    async def _interrogate_http(self, host: str, port: int, use_ssl: bool) -> str:
        url = f"{'https' if use_ssl else 'http'}://{host}:{port}/"
        ua = random.choice(USER_AGENTS) if self.opsec else USER_AGENTS[0]
        headers = {"User-Agent": ua, "Accept": "*/*"}
        info_tags = []
        
        # OPSEC SOCKS Proxy logic
        conn = None
        if self.proxy:
            try:
                from aiohttp_socks import ProxyConnector
                conn = ProxyConnector.from_url(self.proxy)
            except ImportError:
                console.print("[dim yellow][!] aiohttp-socks missing. Ignoring --proxy. Run: pip install aiohttp-socks[/dim yellow]")

        try:
            async with aiohttp.ClientSession(connector=conn, headers=headers) as session:
                async with session.get(url, timeout=self.timeout + 1, ssl=False) as resp:
                    srv = resp.headers.get("Server", "")
                    if srv:
                        info_tags.append(f"Srv: {srv}")
                        if any(w in srv.lower() for w in WAF_SIGNATURES):
                            info_tags.append("🛡️ WAF Detected")
                    
                    if "x-powered-by" in resp.headers:
                        info_tags.append(f"Tech: {resp.headers['x-powered-by']}")
                        
                    html_content = await resp.text()
                    title = re.search(r"(?i)<title>(.*?)</title>", html_content)
                    if title: 
                        info_tags.append(f"Title: '{' '.join(title.group(1).split())[:45]}'")
                    
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                _, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx), timeout=self.timeout)
                cert = writer.get_extra_info("peercert")
                if cert and "subject" in cert:
                    subj = dict(x[0] for x in cert.get("subject", []))
                    info_tags.append(f"🔒 SSL: {subj.get('commonName', 'Unknown')}")
                writer.close()
                await writer.wait_closed()
                
            return " | ".join(info_tags) if info_tags else PORT_SERVICES.get(port, ("Unknown", "", ""))[0]
        except Exception:
            return PORT_SERVICES.get(port, ("Unknown", "", ""))[0]

    async def _interrogate_tcp_banner(self, host: str, port: int) -> str:
        srv_name = PORT_SERVICES.get(port, ("Unknown", "", ""))[0]
        if port in (443, 8443) or "https" in srv_name.lower():
            return await self._interrogate_http(host, port, True)
        if port in (80, 8080) or "http" in srv_name.lower():
            return await self._interrogate_http(host, port, False)

        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=self.timeout)
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                if not data:
                    writer.write(b"\r\n")
                    await writer.drain()
                    data = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            except asyncio.TimeoutError:
                data = b""
            writer.close()
            await writer.wait_closed()

            if data:
                return "".join(c if 32 <= ord(c) < 127 else " " for c in data.decode("utf-8", "replace")).strip()[:80]
        except Exception: 
            pass
        
        return srv_name

    async def _worker(self, queue: asyncio.Queue, progress: Progress, task_id: int) -> None:
        while not self.shutdown_event.is_set():
            item = await queue.get()
            try:
                if item is _SENTINEL or self.shutdown_event.is_set(): 
                    break
                host, port = item
                
                # OPSEC Jitter
                if self.opsec: 
                    await asyncio.sleep(random.uniform(0.01, 0.1))

                # Phase 1: High-speed Raw Discovery
                is_open = await self._raw_udp_check(host, port) if self.udp_mode else await self._raw_tcp_check(host, port)
                
                if is_open:
                    # Phase 2: Deep Interrogation
                    banner = "UDP Response Received" if self.udp_mode else await self._interrogate_tcp_banner(host, port)
                    srv_name, color, _ = PORT_SERVICES.get(port, ("Unknown", "white", "unknown"))
                    vulns = [name for reg, name in HEURISTICS.items() if re.search(reg, banner)]
                    
                    async with self.lock:
                        if host not in self.results: 
                            self.results[host] = {}
                        self.results[host][port] = {
                            "state": "open", "service": srv_name, "info": banner, "vulns": vulns
                        }
                        self.stats["hosts_up"].add(host)
                        self.stats["ports_open"] += 1
                        self.stats["vulns_found"] += len(vulns)

                        proto = "UDP" if self.udp_mode else "TCP"
                        vstr = f" [bold red]🚨 {', '.join(vulns)}[/bold red]" if vulns else ""
                        self.live_discoveries.append(f"[[bold green]+[/bold green]] {host}:{port}/{proto} -> [{color}]{srv_name}[/{color}] ({banner}){vstr}")
                        if len(self.live_discoveries) > 8: 
                            self.live_discoveries.pop(0)

            except Exception: 
                pass
            finally:
                progress.advance(task_id)
                queue.task_done()

    async def engine_async_socket(self) -> None:
        mode_str = "[bold magenta]UDP Engine[/bold magenta]" if self.udp_mode else "[bold blue]TCP Multiplex Matrix[/bold blue]"
        console.print(f"\n[*] Starting {mode_str} (Limit: {self.max_workers} FD)")
        queue: asyncio.Queue = asyncio.Queue(maxsize=self.max_workers * 2)

        progress = Progress(
            SpinnerColumn("dots2"), TextColumn("[bold blue]{task.description}"),
            BarColumn(complete_style="cyan", finished_style="green"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(), TextColumn("[dim]Total: {task.total}[/dim]")
        )
        task_id = progress.add_task("Sweeping...", total=0)

        async def _feeder():
            tot = 0
            async for item in self._target_generator():
                if self.shutdown_event.is_set(): 
                    break
                await queue.put(item)
                tot += 1
                progress.update(task_id, total=tot)
            for _ in range(self.max_workers): 
                await queue.put(_SENTINEL)

        feeder_task = asyncio.create_task(_feeder())
        workers = [asyncio.create_task(self._worker(queue, progress, task_id)) for _ in range(self.max_workers)]

        with Live(refresh_per_second=10) as live:
            while not feeder_task.done() or not queue.empty() or not all(w.done() for w in workers):
                if self.shutdown_event.is_set():
                    feeder_task.cancel()
                    for w in workers: 
                        w.cancel()
                    break
                async with self.lock:
                    content = "\n".join(self.live_discoveries) if self.live_discoveries else "[dim]Scanning footprint...[/dim]"
                    s = self.stats
                    stats_str = f"[green]Hosts:[/green] {len(s['hosts_up'])} | [cyan]Ports:[/cyan] {s['ports_open']} | [red]Vulns:[/red] {s['vulns_found']} | [dim]Limit: {self.rate_limiter.limit}[/dim]"
                
                lay = Layout()
                lay.split_column(
                    Layout(Panel(content, title="⚡ Live Telemetry", border_style="cyan"), ratio=3),
                    Layout(Panel(stats_str, border_style="green"), ratio=1),
                    Layout(progress, ratio=1)
                )
                live.update(lay)
                await asyncio.sleep(0.1)

        await asyncio.gather(feeder_task, *workers, return_exceptions=True)

    # =========================================================================
    # PHASE 3: NMAP HANDOFF
    # =========================================================================
    async def engine_nmap_subprocess(self, specific_targets: Optional[Dict[str, List[int]]] = None) -> None:
        if not shutil.which("nmap"):
            console.print("[bold red][X] Nmap binary missing. Bypassing DPI handoff.[/bold red]")
            return
        if self.shutdown_event.is_set() or self.udp_mode: 
            return

        console.print("\n[*] Handoff: Initiating [bold red]Nmap Deep Packet Inspection Engine[/bold red]")
        nmap_tasks = []
        temp_files = []

        try:
            if specific_targets:
                port_map = {}
                for host, pts in specific_targets.items():
                    if pts: 
                        port_map.setdefault(tuple(sorted(pts)), []).append(host)

                for tup_ports, hosts in port_map.items():
                    fd, path = tempfile.mkstemp(prefix="titan_tgt_", text=True)
                    with os.fdopen(fd, "w") as f: 
                        f.write("\n".join(hosts))
                    xml_fd, xml_path = tempfile.mkstemp(prefix="titan_out_", suffix=".xml", text=True)
                    os.close(xml_fd)
                    temp_files.extend([path, xml_path])
                    _TEMP_FILES_REGISTRY.extend([path, xml_path])

                    pts_str = ",".join(map(str, tup_ports))
                    cmd = ["nmap"] + self.nmap_args + ["-p", pts_str, "-oX", xml_path, "-iL", path]
                    nmap_tasks.append((f"{len(hosts)} hosts → ports {pts_str}", cmd, xml_path))
            
            if not nmap_tasks: 
                return

            async def _run(desc, cmd, xml_out):
                if self.shutdown_event.is_set(): 
                    return
                try:
                    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
                    await proc.communicate()
                    updates = await asyncio.to_thread(self._parse_nmap_xml, xml_out)
                    async with self.lock:
                        for addr, pd in updates.items():
                            if addr not in self.results: 
                                self.results[addr] = {}
                            for pid, nd in pd.items():
                                ex = self.results[addr].get(pid, {})
                                ex_ban = ex.get("info", "")
                                nmap_ban = nd["nmap_banner"]
                                f_ban = f"{ex_ban} ➕ Nmap: {nmap_ban}" if ex_ban and nmap_ban else nmap_ban or ex_ban
                                vulns = list(set([name for r, name in HEURISTICS.items() if re.search(r, f_ban)] + ex.get("vulns", [])))
                                self.results[addr][pid] = {"state": "open", "service": nd["service"], "info": f_ban, "vulns": vulns}
                except asyncio.CancelledError:
                    pass

            with Progress(SpinnerColumn("bouncingBall"), TextColumn("[red]{task.description}"), TimeElapsedColumn()) as prog:
                prog.add_task(f"Executing {len(nmap_tasks)} Nmap sandboxes...", total=len(nmap_tasks))
                await asyncio.gather(*[_run(d, c, x) for d, c, x in nmap_tasks], return_exceptions=True)

        finally:
            for p in temp_files:
                try:
                    os.remove(p)
                    if p in _TEMP_FILES_REGISTRY: 
                        _TEMP_FILES_REGISTRY.remove(p)
                except OSError: 
                    pass

    def _parse_nmap_xml(self, xml_path: str) -> Dict[str, Dict[int, Dict[str, Any]]]:
        updates = {}
        try:
            if not os.path.exists(xml_path) or os.path.getsize(xml_path) == 0: 
                return updates
            for event, elem in ET.iterparse(xml_path, events=("end",)):
                if elem.tag == "host":
                    addr_elem = elem.find("address")
                    if addr_elem is None or not addr_elem.get("addr"):
                        elem.clear()
                        continue
                    addr = addr_elem.get("addr")
                    host_data = {}
                    for port_elem in elem.findall(".//port"):
                        try: 
                            pid = int(port_elem.get("portid", 0))
                        except ValueError: 
                            continue
                        
                        state_node = port_elem.find("state")
                        if state_node is None or state_node.get("state") not in ("open", "open|filtered"): 
                            continue
                            
                        srv = port_elem.find("service")
                        nmap_banner = f"{srv.get('product', '')} {srv.get('version', '')}".strip() if srv is not None else ""
                        host_data[pid] = {"service": srv.get("name", "unknown").upper() if srv is not None else "UNKNOWN", "nmap_banner": nmap_banner}
                    
                    if host_data: 
                        updates[addr] = host_data
                    elem.clear()
        except Exception: 
            pass
        return updates

    async def engine_hybrid(self) -> None:
        await self.engine_async_socket()
        if self.shutdown_event.is_set(): 
            return
        open_targets = {h: list(p.keys()) for h, p in self.results.items() if p}
        if open_targets and not self.udp_mode:
            await self.engine_nmap_subprocess(specific_targets=open_targets)

    def display_results(self) -> None:
        console.print("\n")
        has_results = False
        proto = "udp" if self.udp_mode else "tcp"
        for host, ports in sorted(self.results.items()):
            if not ports: 
                continue
            has_results = True
            root_tree = Tree(f"🌐 [bold white]Host:[/bold white] [bold cyan]{host}[/bold cyan]")
            table = Table(show_header=True, header_style="bold magenta", box=None, padding=(0, 2))
            table.add_column("Port"); table.add_column("State"); table.add_column("Service"); table.add_column("App Intel / Vulnerability")

            for p in sorted(ports.keys()):
                d = ports[p]
                _, color, _ = PORT_SERVICES.get(p, ("Unknown", "white", "unknown"))
                safe_info = str(d["info"]).replace("[", r"\[").replace("]", r"\]")
                if d.get("vulns"): 
                    safe_info = f"[bold red]🚨 VULN: {', '.join(d['vulns'])}[/bold red] | " + safe_info
                table.add_row(f"[{color}]{p}/{proto}[/{color}]", "[bold green]OPEN[/bold green]", f"[{color}]{d['service']}[/{color}]", f"[dim white]{safe_info}[/dim white]")
            root_tree.add(table)
            console.print(Panel(root_tree, border_style="cyan"))

        if not has_results:
            console.print("[bold yellow][!] Scan complete. Zero digital footprint detected.[/bold yellow]")
