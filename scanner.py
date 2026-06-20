import asyncio
import argparse
import ipaddress
import os
import sys
import ssl
import re
import shlex
import socket
import tempfile
import threading
import shutil
import random
from typing import AsyncGenerator, Dict, Any, Set, List, Optional, Tuple
from datetime import datetime

# Import components from our separated modules
from constants import PORT_SERVICES, WAF_SIGNATURES, USER_AGENTS, HEURISTICS, SAFE_NMAP_FLAGS, _SENTINEL
from utils import _TEMP_FILES_REGISTRY

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.tree import Tree
from rich.table import Table
from rich.live import Live
from rich.layout import Layout

console = Console()

try:
    import defusedxml.ElementTree as ET
except ImportError:
    sys.exit(
        "[FATAL] defusedxml is required: pip install defusedxml\n"
        "Falling back to stdlib xml.etree.ElementTree is intentionally disabled "
        "to prevent XXE attacks via malicious Nmap XML output."
    )

class OmniScanTitan:
    def __init__(self, args: argparse.Namespace) -> None:
        self.max_workers = self._optimize_os_limits(args.workers)
        self.raw_targets = self._get_raw_targets(args.target, args.input_file)
        self.ports = self._parse_ports(args.ports)
        self.mode = args.mode
        self.timeout = args.timeout
        self.nmap_args = self._validate_nmap_args(args.nmap_args)

        self.results: Dict[str, Dict[int, Dict[str, Any]]] = {}
        self.live_discoveries: List[str] = []
        self.stats: Dict[str, Any] = {
            "hosts_up": set(), "ports_open": 0, "vulns_found": 0
        }

        self.lock = asyncio.Lock()
        self.shutdown_event = asyncio.Event()
        self._dns_semaphore = asyncio.Semaphore(64)
        self._thread_lock = threading.Lock()

    @staticmethod
    def _optimize_os_limits(requested_workers: int) -> int:
        if os.name != "nt":
            try:
                import resource
                soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
                target_limit = min(hard if hard > 0 else 65535, 65535)
                if soft < target_limit:
                    resource.setrlimit(resource.RLIMIT_NOFILE, (target_limit, hard))
                return min(requested_workers, target_limit - 100)
            except Exception:
                return min(requested_workers, 1024)
        return min(requested_workers, 1000)

    @staticmethod
    def _get_raw_targets(target_str: Optional[str], input_file: Optional[str]) -> Set[str]:
        raw: Set[str] = set()
        if target_str:
            raw.add(target_str)
        if input_file and os.path.exists(input_file):
            with open(input_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        raw.add(line)
        if not raw:
            console.print("[bold red][X] Error: No valid targets provided.[/bold red]")
            sys.exit(1)
        return raw

    @staticmethod
    def _parse_ports(port_string: str) -> List[int]:
        if port_string.lower() == "top":
            return list(PORT_SERVICES.keys())
        if port_string.lower() == "all":
            return list(range(1, 65536))

        ports: Set[int] = set()
        for part in port_string.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                try:
                    start, end = map(int, part.split("-", 1))
                    ports.update(p for p in range(start, end + 1) if 1 <= p <= 65535)
                except ValueError:
                    pass
            elif part.isdigit():
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
        
        if not ports:
            console.print("[bold red][X] Error: No valid ports parsed.[/bold red]")
            sys.exit(1)
        return sorted(ports)

    @staticmethod
    def _validate_nmap_args(raw_args: str) -> List[str]:
        try:
            tokens = shlex.split(raw_args)
        except ValueError as exc:
            console.print(f"[bold red][!] Invalid --nmap-args quoting: {exc}[/bold red]")
            sys.exit(1)

        _SAFE_VALUE_RE = re.compile(r"^[A-Za-z0-9.\-_:]+$")
        rejected: List[str] = []
        for token in tokens:
            if token.startswith("-"):
                if token not in SAFE_NMAP_FLAGS:
                    rejected.append(token)
            else:
                if not _SAFE_VALUE_RE.match(token):
                    rejected.append(token)

        if rejected:
            console.print(
                f"[bold red][!] Unsafe/disallowed nmap token(s) rejected: {', '.join(rejected)}[/bold red]"
            )
            sys.exit(1)
        return tokens

    async def _resolve_target(self, target: str) -> AsyncGenerator[str, None]:
        loop = asyncio.get_running_loop()
        try:
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

            async with self._dns_semaphore:
                try:
                    info = await asyncio.wait_for(
                        loop.getaddrinfo(target, None, family=socket.AF_INET),
                        timeout=5.0,
                    )
                    yield info[0][4][0]
                except (asyncio.TimeoutError, OSError):
                    pass
        except Exception:
            pass

    async def _target_generator(self) -> AsyncGenerator[Tuple[str, int], None]:
        for t in self.raw_targets:
            async for ip in self._resolve_target(t):
                for port in self.ports:
                    if self.shutdown_event.is_set():
                        return
                    yield (ip, port)

    @staticmethod
    def _check_heuristics(banner: str) -> List[str]:
        return [name for regex, name in HEURISTICS.items() if re.search(regex, banner)]

    async def _analyze_http(self, host: str, port: int, use_ssl: bool) -> str:
        ua = random.choice(USER_AGENTS)
        request = (
            f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n"
        ).encode()
        info_tags: List[str] = []
        writer: Optional[asyncio.StreamWriter] = None
        
        try:
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ctx),
                    timeout=self.timeout + 2,
                )
                cert = writer.get_extra_info("peercert")
                if cert:
                    subj = dict(x[0] for x in cert.get("subject", []))
                    info_tags.append(f"SSL: {subj.get('commonName', 'Unknown')}")
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout,
                )

            writer.write(request)
            await writer.drain()

            resp_bytes = await asyncio.wait_for(reader.read(16384), timeout=self.timeout)
            resp_str = resp_bytes.decode("utf-8", errors="replace")
            lines = resp_str.splitlines()
            if lines:
                info_tags.append(f"[{lines[0].strip()[:80]}]")

            headers = dict(re.findall(r"(?i)^([a-z0-9-]+):\s*(.+)$", resp_str, re.MULTILINE))

            if "server" in headers:
                srv = headers["server"].strip()
                info_tags.append(f"Srv: {srv}")
                if any(w in srv.lower() for w in WAF_SIGNATURES):
                    info_tags.append("🛡️ WAF Detected")

            if "x-powered-by" in headers:
                info_tags.append(f"Tech: {headers['x-powered-by'].strip()}")

            title = re.search(r"(?i)<title>(.*?)</title>", resp_str, re.DOTALL)
            if title:
                info_tags.append(f"Title: '{' '.join(title.group(1).split())[:45]}'")

            return " | ".join(info_tags) if info_tags else PORT_SERVICES.get(port, ("Unknown", "", ""))[0]

        except Exception:
            return PORT_SERVICES.get(port, ("Unknown", "", ""))[0]
        finally:
            if writer is not None:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

    async def _smart_banner_grab(self, host: str, port: int) -> str:
        srv_name = PORT_SERVICES.get(port, ("Unknown", "white", "unknown"))[0]
        if port in (443, 8443) or "https" in srv_name.lower():
            return await self._analyze_http(host, port, use_ssl=True)
        if port in (80, 8080) or "http" in srv_name.lower():
            return await self._analyze_http(host, port, use_ssl=False)

        writer: Optional[asyncio.StreamWriter] = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout
            )
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            except asyncio.TimeoutError:
                writer.write(b"\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)

            if data:
                clean = "".join(c if 32 <= ord(c) < 127 else " " for c in data.decode("utf-8", errors="replace"))
                return clean.strip()[:80]
        except Exception:
            pass
        finally:
            if writer is not None:
                try:
                    writer.close()
                    await writer.wait_closed()
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
                banner = await self._smart_banner_grab(host, port)
                srv_name, color, _ = PORT_SERVICES.get(port, ("Unknown", "white", "unknown"))
                vulns = self._check_heuristics(banner)
                vuln_str = f" [bold red]🚨 {', '.join(vulns)}[/bold red]" if vulns else ""

                async with self.lock:
                    if host not in self.results:
                        self.results[host] = {}
                    self.results[host][port] = {
                        "state":   "open",
                        "service": srv_name,
                        "info":    banner,
                        "vulns":   vulns,
                    }
                    self.stats["hosts_up"].add(host)
                    self.stats["ports_open"] += 1
                    self.stats["vulns_found"] += len(vulns)

                    msg = f"[[bold green]+[/bold green]] {host}:{port} -> [{color}]{srv_name}[/{color}] ({banner}){vuln_str}"
                    self.live_discoveries.append(msg)
                    if len(self.live_discoveries) > 8:
                        self.live_discoveries.pop(0)

            except Exception:
                pass
            finally:
                progress.advance(task_id)
                queue.task_done()

    async def _feeder(self, queue: asyncio.Queue, progress: Progress, task_id: int, num_workers: int) -> None:
        try:
            total_items = 0
            async for item in self._target_generator():
                if self.shutdown_event.is_set():
                    break
                await queue.put(item)
                total_items += 1
                progress.update(task_id, total=total_items)
        except Exception as exc:
            console.print(f"[bold red]Feeder Error: {exc}[/bold red]")
        finally:
            for _ in range(num_workers):
                await queue.put(_SENTINEL)

    async def engine_async_socket(self) -> None:
        console.print(f"\n[*] Starting [bold blue]Titan Async Matrix[/bold blue] (Concurrency: {self.max_workers})")
        queue: asyncio.Queue = asyncio.Queue(maxsize=self.max_workers * 2)

        progress = Progress(
            SpinnerColumn("dots2"),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(complete_style="cyan", finished_style="green"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            TextColumn("[dim]Total: {task.total}[/dim]"),
        )
        task_id = progress.add_task("Sweeping...", total=0)

        feeder_task = asyncio.create_task(self._feeder(queue, progress, task_id, self.max_workers))
        workers = [asyncio.create_task(self._worker(queue, progress, task_id)) for _ in range(self.max_workers)]

        with Live(refresh_per_second=10) as live:
            while not feeder_task.done() or not queue.empty() or not all(w.done() for w in workers):
                if self.shutdown_event.is_set():
                    feeder_task.cancel()
                    for w in workers:
                        w.cancel()
                    break
                async with self.lock:
                    content = "\n".join(self.live_discoveries) if self.live_discoveries else "[dim]Scanning digital footprint...[/dim]"
                    stats_str = (
                        f"[green]Hosts Up:[/green] {len(self.stats['hosts_up'])} "
                        f"| [cyan]Ports:[/cyan] {self.stats['ports_open']} "
                        f"| [red]Vulns:[/red] {self.stats['vulns_found']}"
                    )
                combined = Layout()
                combined.split_column(
                    Layout(Panel(content, title="⚡ Live Telemetry", border_style="cyan"), ratio=3),
                    Layout(Panel(stats_str, border_style="green"), ratio=1),
                    Layout(progress, ratio=1),
                )
                live.update(combined)
                await asyncio.sleep(0.1)

        await asyncio.gather(feeder_task, *workers, return_exceptions=True)

    async def engine_nmap_subprocess(self, specific_targets: Optional[Dict[str, List[int]]] = None) -> None:
        if not shutil.which("nmap"):
            console.print("[bold red][X] Nmap not found in PATH! Bypassing DPI engine.[/bold red]")
            return
        if self.shutdown_event.is_set():
            return

        console.print("\n[*] Initiating [bold red]Nmap Deep Packet Inspection Engine[/bold red]")
        nmap_tasks: List[Tuple[str, List[str], str]] = []
        temp_files: List[str] = []

        try:
            if specific_targets:
                port_map: Dict[Tuple[int, ...], List[str]] = {}
                for host, ports in specific_targets.items():
                    if ports:
                        port_map.setdefault(tuple(sorted(ports)), []).append(host)

                for tup_ports, hosts in port_map.items():
                    fd, path = tempfile.mkstemp(prefix="titan_targets_", text=True)
                    with os.fdopen(fd, "w") as f:
                        f.write("\n".join(hosts))
                    xml_fd, xml_path = tempfile.mkstemp(prefix="titan_out_", suffix=".xml", text=True)
                    os.close(xml_fd)
                    temp_files.extend([path, xml_path])
                    _TEMP_FILES_REGISTRY.extend([path, xml_path])

                    ports_str = ",".join(map(str, tup_ports))
                    cmd = ["nmap"] + self.nmap_args + ["-p", ports_str, "-oX", xml_path, "-iL", path]
                    nmap_tasks.append((f"{len(hosts)} hosts → ports {ports_str}", cmd, xml_path))
            else:
                resolved_ips: List[str] = []
                for raw_target in self.raw_targets:
                    async for ip in self._resolve_target(raw_target):
                        resolved_ips.append(ip)

                if not resolved_ips:
                    return

                fd, path = tempfile.mkstemp(prefix="titan_targets_", text=True)
                with os.fdopen(fd, "w") as f:
                    f.write("\n".join(resolved_ips))
                xml_fd, xml_path = tempfile.mkstemp(prefix="titan_out_", suffix=".xml", text=True)
                os.close(xml_fd)
                temp_files.extend([path, xml_path])
                _TEMP_FILES_REGISTRY.extend([path, xml_path])

                ports_str = ",".join(map(str, self.ports))
                cmd = ["nmap"] + self.nmap_args + ["-p", ports_str, "-oX", xml_path, "-iL", path]
                nmap_tasks.append((f"{len(resolved_ips)} resolved hosts", cmd, xml_path))

            if not nmap_tasks:
                return

            async def _run_nmap_task(desc: str, cmd: List[str], xml_out: str) -> None:
                if self.shutdown_event.is_set():
                    return
                try:
                    process = await asyncio.create_subprocess_exec(
                        *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
                    )
                    await process.communicate()
                    updates = await asyncio.to_thread(self._parse_nmap_xml, xml_out)
                    
                    if updates:
                        async with self.lock:
                            for addr, ports in updates.items():
                                if addr not in self.results: 
                                    self.results[addr] = {}
                                for port_id, nd in ports.items():
                                    existing = self.results[addr].get(port_id, {})
                                    existing_banner = existing.get("info", "")
                                    nmap_banner = nd["nmap_banner"]
                                    
                                    if nmap_banner:
                                        final_banner = f"{existing_banner} ➕ Nmap: {nmap_banner}" if existing_banner and existing_banner != "Unknown" else nmap_banner
                                    else:
                                        final_banner = existing_banner or "No detailed banner"
                                        
                                    vulns = list(set(self._check_heuristics(final_banner) + existing.get("vulns", [])))
                                    self.results[addr][port_id] = {"state": "open", "service": nd["service"], "info": final_banner, "vulns": vulns}
                                    self.stats["hosts_up"].add(addr)
                except Exception as exc:
                    console.print(f"[bold red][!] Nmap Error on {desc}: {exc}[/bold red]")

            with Progress(SpinnerColumn("bouncingBall"), TextColumn("[red]{task.description}"), TimeElapsedColumn()) as progress:
                progress.add_task(f"Executing {len(nmap_tasks)} Nmap task(s) in parallel...", total=len(nmap_tasks))
                results = await asyncio.gather(
                    *[_run_nmap_task(desc, cmd, xml_out) for desc, cmd, xml_out in nmap_tasks],
                    return_exceptions=True,
                )
                for i, res in enumerate(results):
                    if isinstance(res, Exception):
                        console.print(f"[bold red][!] Nmap task '{nmap_tasks[i][0]}' failed: {res}[/bold red]")

        finally:
            for path in temp_files:
                try:
                    os.remove(path)
                    if path in _TEMP_FILES_REGISTRY:
                        _TEMP_FILES_REGISTRY.remove(path)
                except OSError:
                    pass

    def _parse_nmap_xml(self, xml_path: str) -> None:
        try:
            if not os.path.exists(xml_path) or os.path.getsize(xml_path) == 0:
                return
            tree = ET.parse(xml_path)
            updates: Dict[str, Dict[int, Dict[str, Any]]] = {}

            for host_elem in tree.getroot().findall("host"):
                addr_elem = host_elem.find("address")
                if addr_elem is None or not addr_elem.get("addr"): continue
                addr = addr_elem.get("addr")
                host_data: Dict[int, Dict[str, Any]] = {}

                for port_elem in host_elem.findall(".//port"):
                    try: port_id = int(port_elem.get("portid", 0))
                    except ValueError: continue

                    state_elem = port_elem.find("state")
                    if state_elem is None or state_elem.get("state") not in ("open", "open|filtered"):
                        continue

                    srv = port_elem.find("service")
                    name = srv.get("name", "unknown") if srv is not None else "unknown"
                    product = srv.get("product", "") if srv is not None else ""
                    version = srv.get("version", "") if srv is not None else ""
                    nmap_banner = f"{product} {version}".strip()

                    host_data[port_id] = {"state": "open", "service": name.upper(), "nmap_banner": nmap_banner}

                if host_data:
                    updates[addr] = host_data

            

        except Exception as exc:
            console.print(f"[dim red]Error processing Nmap output: {exc}[/dim red]")

        return updates

    async def engine_hybrid(self) -> None:
        await self.engine_async_socket()
        if self.shutdown_event.is_set(): return
        open_targets = {h: list(p.keys()) for h, p in self.results.items() if p}
        if open_targets:
            console.print(f"\n[*] Handoff: [bold green]{sum(len(p) for p in open_targets.values())}[/bold green] open ports transferred to Nmap engine.")
            await self.engine_nmap_subprocess(specific_targets=open_targets)
        else:
            console.print("\n[yellow][!] No open ports discovered. Bypassing Nmap engine.[/yellow]")

    def display_results(self) -> None:
        console.print("\n")
        has_results = False
        for host, ports in sorted(self.results.items()):
            if not ports: continue
            has_results = True
            root_tree = Tree(f"🌐 [bold white]Host:[/bold white] [bold cyan]{host}[/bold cyan]")
            table = Table(show_header=True, header_style="bold magenta", box=None, padding=(0, 2))
            table.add_column("Port"); table.add_column("State"); table.add_column("Service"); table.add_column("Vulnerability / App Info")

            for p in sorted(ports.keys()):
                d = ports[p]
                _, color, _ = PORT_SERVICES.get(p, ("Unknown", "white", "unknown"))
                safe_info = str(d["info"]).replace("[", r"\[").replace("]", r"\]").replace(r"\[bold red]", "[bold red]").replace(r"\[/bold red]", "[/bold red]")
                if d.get("vulns"): safe_info = f"[bold red]🚨 VULN: {', '.join(d['vulns'])}[/bold red] | " + safe_info
                table.add_row(f"[{color}]{p}/tcp[/{color}]", "[bold green]OPEN[/bold green]", f"[{color}]{d['service']}[/{color}]", f"[dim white]{safe_info}[/dim white]")
            root_tree.add(table)
            console.print(Panel(root_tree, border_style="cyan"))

        if not has_results:
            console.print("[bold yellow][!] Scan complete. No open ports discovered.[/bold yellow]")
