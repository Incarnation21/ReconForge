"""
Port Scanner Module.
Native async TCP connect scanner with service banner grabbing.
Optional Nmap integration for service version detection.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Optional

from reconforge.core.models import Finding, PortInfo, Severity
from reconforge.core.module import BaseModule, ModuleResult, register_module
from reconforge.core.context import ScanContext
from reconforge.core.limiter import RateLimitContext

logger = logging.getLogger(__name__)

# Top 1000 ports (most common subset for recon)
TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888, 9200, 27017,
]

TOP_1000_PORTS = TOP_100_PORTS + [
    20, 24, 26, 69, 79, 81, 82, 88, 102, 104, 106, 109, 113, 119, 123, 137,
    138, 158, 179, 194, 213, 264, 389, 427, 465, 514, 515, 543, 544, 548,
    554, 587, 593, 631, 636, 646, 873, 990, 992, 1025, 1026, 1027, 1028,
    1029, 1110, 1433, 1434, 1521, 1720, 1900, 2000, 2001, 2049, 2121, 2717,
    3000, 3001, 3128, 3268, 3269, 4443, 4848, 5000, 5001, 5432, 5985, 5986,
    6379, 6443, 7001, 7474, 8008, 8009, 8081, 8082, 8083, 8084, 8085,
    8086, 8087, 8088, 8089, 8090, 8180, 8181, 8333, 8400, 8800, 9000,
    9001, 9080, 9090, 9100, 9300, 9418, 9999, 10000, 10443, 11211, 27017,
    27018, 27019, 28017, 50000, 50001,
]

SERVICE_SIGNATURES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch",
    27017: "mongodb",
}

DANGEROUS_PORTS = {
    23: ("Telnet Service Detected", Severity.HIGH, "Telnet transmits credentials in plaintext."),
    21: ("FTP Service Detected", Severity.MEDIUM, "FTP may transmit credentials in plaintext."),
    3389: ("RDP Exposed", Severity.HIGH, "Remote Desktop Protocol exposed to internet."),
    5900: ("VNC Exposed", Severity.HIGH, "VNC service exposed - potential unauthorized access."),
    6379: ("Redis Exposed (Unauthenticated)", Severity.CRITICAL, "Redis may be accessible without authentication."),
    27017: ("MongoDB Exposed", Severity.CRITICAL, "MongoDB may be accessible without authentication."),
    9200: ("Elasticsearch Exposed", Severity.HIGH, "Elasticsearch API may be unauthenticated."),
    11211: ("Memcached Exposed", Severity.HIGH, "Memcached exposed - potential amplification and data leak."),
}


@register_module
class PortScanModule(BaseModule):
    NAME = "portscan"
    DESCRIPTION = "Async TCP connect scanner with service detection and banner grabbing"
    REQUIRES = {"ip_map"}
    PROVIDES = {"open_ports", "web_services"}

    def _get_ports(self) -> list[int]:
        cfg_ports = self.ctx.config.ports
        if cfg_ports == "top100":
            return TOP_100_PORTS
        elif cfg_ports == "top1000":
            return TOP_1000_PORTS
        elif cfg_ports == "all":
            return list(range(1, 65536))
        else:
            try:
                return [int(p.strip()) for p in cfg_ports.split(",") if p.strip().isdigit()]
            except ValueError:
                return TOP_1000_PORTS

    async def run(self) -> ModuleResult:
        hosts = self.ctx.store.get_all_hosts()
        ports = self._get_ports()
        self.logger.info(f"Scanning {len(hosts)} hosts across {len(ports)} ports")

        total_open = 0
        sem = asyncio.Semaphore(500)

        for hostname in hosts:
            host = self.ctx.store.get_host(hostname)
            scan_targets = host.ip_addresses if (host and host.ip_addresses) else [hostname]

            for ip in scan_targets:
                open_ports = await self._scan_host(ip, ports, sem)
                if open_ports:
                    total_open += len(open_ports)
                    await self.ctx.store.update_host(hostname, open_ports=open_ports)
                    await self._analyze_findings(hostname, ip, open_ports)

        self.ctx.set("open_ports_scanned", True)
        return ModuleResult(
            module_name=self.NAME,
            success=True,
            data={"hosts_scanned": len(hosts), "ports_per_host": len(ports), "total_open": total_open},
        )

    async def _scan_host(self, ip: str, ports: list[int], sem: asyncio.Semaphore) -> list[PortInfo]:
        tasks = [self._check_port(ip, port, sem) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        open_ports = [r for r in results if isinstance(r, PortInfo)]
        if open_ports:
            self.logger.info(f"{ip}: {len(open_ports)} open ports: {[p.port for p in open_ports]}")
        return open_ports

    async def _check_port(self, ip: str, port: int, sem: asyncio.Semaphore) -> Optional[PortInfo]:
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.ctx.config.timeout,
                )
                banner = await self._grab_banner(reader, writer, port)
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                except Exception:
                    pass

                service = SERVICE_SIGNATURES.get(port, "unknown")
                version = self._parse_version(banner, service) if banner else None

                return PortInfo(
                    port=port,
                    protocol="tcp",
                    state="open",
                    service=service,
                    banner=banner,
                    version=version,
                )
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None
            except Exception as e:
                logger.debug(f"Port {ip}:{port} error: {e}")
                return None

    async def _grab_banner(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int) -> Optional[str]:
        """Attempt to grab service banner with protocol-specific probes."""
        try:
            # Send probes for specific services
            probes = {
                22: None,  # SSH sends banner automatically
                25: None,  # SMTP sends banner
                21: None,  # FTP sends banner
                3306: None, # MySQL sends banner
                6379: b"PING\r\n",
                9200: b"GET / HTTP/1.0\r\n\r\n",
            }
            if port in probes and probes[port]:
                writer.write(probes[port])
                await writer.drain()
            elif port in (80, 8080, 8081, 8082, 8443, 443):
                writer.write(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                await writer.drain()

            data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            if data:
                return data.decode("utf-8", errors="replace").strip()[:256]
        except Exception:
            pass
        return None

    def _parse_version(self, banner: str, service: str) -> Optional[str]:
        """Extract version string from banner."""
        patterns = [
            r"OpenSSH[_-]([\d.]+[p\d]*)",
            r"Apache[/ ]([\d.]+)",
            r"nginx[/ ]([\d.]+)",
            r"Microsoft-IIS[/ ]([\d.]+)",
            r"SSH-\d\.\d-([\S]+)",
            r"([\d]+\.[\d]+\.[\d]+(?:\.[\d]+)?)",
        ]
        for pat in patterns:
            m = re.search(pat, banner, re.IGNORECASE)
            if m:
                return m.group(1)
        return None

    async def _analyze_findings(self, hostname: str, ip: str, ports: list[PortInfo]) -> None:
        """Generate findings for dangerous open services."""
        open_port_nums = {p.port for p in ports}
        for port_num, (title, severity, desc) in DANGEROUS_PORTS.items():
            if port_num in open_port_nums:
                await self.ctx.store.add_finding(Finding(
                    id=self._make_finding_id(f"{hostname}-port{port_num}"),
                    title=title,
                    severity=severity,
                    description=f"{desc} Target: {hostname} ({ip})",
                    target=hostname,
                    module=self.NAME,
                    evidence=f"Port {port_num}/tcp open on {ip}",
                    recommendation=f"Restrict access to port {port_num} using firewall rules. Ensure authentication is required.",
                ))
