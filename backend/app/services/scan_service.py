"""
Port Scanning Service — Shadow Spike
Uses asyncio sockets for reliable, dependency-free port scanning.
Falls back gracefully without requiring nmap binary.
"""
import asyncio
import json
import socket
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

# Well-known port -> service mapping
KNOWN_SERVICES: Dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
    110: "pop3", 119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    162: "snmp-trap", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 514: "syslog", 515: "printer", 587: "submission",
    631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1080: "socks", 1433: "mssql", 1434: "mssql-m", 1521: "oracle",
    1723: "pptp", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    5901: "vnc-1", 6379: "redis", 8000: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 8888: "http-alt", 9090: "zeus-admin",
    9200: "elasticsearch", 9300: "elasticsearch", 27017: "mongodb",
}

# Dangerous ports that raise risk level
HIGH_RISK_PORTS = {21, 23, 135, 137, 138, 139, 445, 1433, 3389, 5900}
MEDIUM_RISK_PORTS = {22, 25, 53, 110, 143, 161, 389, 514, 1521, 3306, 5432, 6379, 27017}

# Port lists by scan type
TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
    513, 514, 515, 543, 544, 548, 554, 587, 631, 636, 646, 873, 990, 993,
    995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900,
    2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000,
    5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
    6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999,
    10000, 32768, 49152, 49153, 49154, 49155, 49156
]

TOP_1000_PORTS = sorted(set(TOP_100_PORTS + list(range(1, 1025)) + [
    1080, 1194, 1241, 1311, 1434, 1521, 1604, 1723, 1883, 2049, 2082, 2083,
    2222, 2375, 2376, 3000, 3128, 3268, 3269, 3306, 3389, 4000, 4443, 4444,
    4848, 5000, 5432, 5555, 5900, 5984, 6379, 6443, 6660, 6661, 6662, 6663,
    6664, 6665, 6666, 6667, 6668, 6669, 7001, 7002, 7070, 7071, 8000, 8008,
    8009, 8080, 8081, 8443, 8444, 8888, 8983, 9000, 9090, 9200, 9300, 9418,
    9999, 10000, 10250, 10443, 11211, 27017, 27018, 28017, 50000, 50030, 50070
]))


def get_ports_for_scan(scan_type: str, custom_ports: Optional[str] = None) -> List[int]:
    """Return list of ports to scan based on scan type."""
    if scan_type == "quick":
        return TOP_100_PORTS
    elif scan_type == "standard":
        return TOP_1000_PORTS
    elif scan_type == "full":
        return list(range(1, 65536))
    elif scan_type == "custom" and custom_ports:
        ports = set()
        for part in custom_ports.replace(" ", "").split(","):
            if "-" in part:
                start, end = part.split("-", 1)
                for p in range(int(start), int(end) + 1):
                    if 1 <= p <= 65535:
                        ports.add(p)
            else:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
        return sorted(ports)
    return TOP_100_PORTS


# Ports where we send an HTTP probe instead of passive banner grab
HTTP_PORTS = {80, 443, 8000, 8080, 8443, 8888, 9090, 3000, 5000, 8008, 8081, 5173}


async def grab_banner(target: str, port: int, timeout: float = 3.0) -> str:
    """Connect to an open port and try to read its banner/version string."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port),
            timeout=timeout
        )

        banner = ""
        if port in HTTP_PORTS:
            # Send minimal HTTP request to get Server header
            writer.write(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                response = data.decode('utf-8', errors='ignore')
                # Extract Server header
                for line in response.split('\r\n'):
                    if line.lower().startswith('server:'):
                        banner = line.split(':', 1)[1].strip()
                        break
                if not banner:
                    # Try first line for HTTP version
                    first_line = response.split('\r\n')[0] if response else ''
                    if first_line.startswith('HTTP/'):
                        banner = first_line
            except:
                pass
        else:
            # Passive banner grab — many services send a greeting on connect
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                banner = data.decode('utf-8', errors='ignore').strip()
            except:
                pass

            # Fallback HTTP request if passive fails (catches unknown web services)
            if not banner:
                try:
                    writer.write(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
                    await writer.drain()
                    data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                    response = data.decode('utf-8', errors='ignore')
                    for line in response.split('\r\n'):
                        if line.lower().startswith('server:'):
                            banner = line.split(':', 1)[1].strip()
                            break
                    if not banner:
                        first_line = response.split('\r\n')[0] if response else ''
                        if first_line.startswith('HTTP/'):
                            banner = first_line
                except:
                    pass

        writer.close()
        try:
            await writer.wait_closed()
        except:
            pass

        # Clean up banner — take first meaningful line, limit length
        if banner:
            banner = banner.split('\n')[0].strip()
            banner = banner.replace('\r', '').replace('\x00', '')
            # Remove ANSI escape codes
            import re
            banner = re.sub(r'\x1b\[[0-9;]*m', '', banner)
            if len(banner) > 120:
                banner = banner[:120] + '...'
        return banner
    except:
        return ""


async def scan_port(target: str, port: int, timeout: float = 1.5) -> Tuple[int, str]:
    """Scan a single port. Returns (port, state)."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return (port, "open")
    except asyncio.TimeoutError:
        return (port, "filtered")
    except ConnectionRefusedError:
        return (port, "closed")
    except OSError:
        return (port, "closed")
    except Exception:
        return (port, "closed")


async def run_port_scan(
    target: str,
    scan_type: str = "quick",
    custom_ports: Optional[str] = None,
    concurrency: int = 200,
    progress_callback=None,
    cancel_event: Optional[asyncio.Event] = None
) -> dict:
    """
    Run a full port scan against the target.
    Returns a dict with ports info, counts, risk level, and duration.
    """
    start_time = datetime.now(timezone.utc)
    ports_to_scan = get_ports_for_scan(scan_type, custom_ports)

    # Resolve hostname first
    try:
        resolved_ip = socket.gethostbyname(target)
    except socket.gaierror:
        return {
            "error": f"Cannot resolve hostname: {target}",
            "ports": [],
            "total_open": 0,
            "total_closed": 0,
            "total_filtered": 0,
            "risk_level": None,
            "scan_duration": 0
        }

    # Use semaphore to limit concurrency
    semaphore = asyncio.Semaphore(concurrency)
    scanned_count = 0
    total_ports = len(ports_to_scan)

    async def limited_scan(port):
        if cancel_event and cancel_event.is_set():
            return (port, "filtered")

        nonlocal scanned_count
        async with semaphore:
            if cancel_event and cancel_event.is_set():
                return (port, "filtered")
            res = await scan_port(resolved_ip, port)
        
        scanned_count += 1
        
        if progress_callback:
            # Emit progress update (every few ports to avoid spam)
            if scanned_count % max(1, total_ports // 20) == 0 or scanned_count == total_ports:
                await progress_callback({
                    "type": "progress",
                    "progress": (scanned_count / total_ports) * 100
                })
            
            # Immediately notify if port is open
            if res[1] == "open":
                await progress_callback({
                    "type": "port_found",
                    "data": {
                        "port": port,
                        "state": "open",
                        "service": KNOWN_SERVICES.get(port, "unknown"),
                        "version": ""
                    }
                })
        return res

    # Run all port scans concurrently
    tasks = [limited_scan(p) for p in ports_to_scan]
    results = await asyncio.gather(*tasks)

    # Process results
    open_ports = []
    closed_count = 0
    filtered_count = 0

    for port, state in results:
        if state == "open":
            service = KNOWN_SERVICES.get(port, "unknown")
            open_ports.append({
                "port": port,
                "state": "open",
                "service": service,
                "version": ""  # will be filled by banner grab
            })
        elif state == "filtered":
            filtered_count += 1
        else:
            closed_count += 1

    # Sort open ports
    open_ports.sort(key=lambda x: x["port"])

    # Phase 2: Banner grabbing for version detection on open ports
    if open_ports:
        banner_semaphore = asyncio.Semaphore(50)  # lower concurrency for banners

        async def grab_with_limit(port_info):
            if cancel_event and cancel_event.is_set():
                return

            async with banner_semaphore:
                if cancel_event and cancel_event.is_set():
                    return
                banner = await grab_banner(resolved_ip, port_info["port"])
                if banner:
                    port_info["version"] = banner
                    # Try to improve service name from banner
                    banner_lower = banner.lower()
                    if "ssh" in banner_lower and port_info["service"] == "unknown":
                        port_info["service"] = "ssh"
                    elif ("http" in banner_lower or "apache" in banner_lower or "nginx" in banner_lower) and port_info["service"] == "unknown":
                        port_info["service"] = "http"
                    elif "smtp" in banner_lower and port_info["service"] == "unknown":
                        port_info["service"] = "smtp"
                    elif "ftp" in banner_lower and port_info["service"] == "unknown":
                        port_info["service"] = "ftp"
                    elif "mysql" in banner_lower and port_info["service"] == "unknown":
                        port_info["service"] = "mysql"
                    elif "redis" in banner_lower and port_info["service"] == "unknown":
                        port_info["service"] = "redis"
                    elif "postgres" in banner_lower and port_info["service"] == "unknown":
                        port_info["service"] = "postgresql"
                    elif "mongo" in banner_lower and port_info["service"] == "unknown":
                        port_info["service"] = "mongodb"
                    
                    if progress_callback:
                        await progress_callback({
                            "type": "port_updated",
                            "data": port_info
                        })

        banner_tasks = [grab_with_limit(p) for p in open_ports]
        await asyncio.gather(*banner_tasks)

    # Compute risk level
    risk_level, risk_reason = compute_risk_level(open_ports)

    end_time = datetime.now(timezone.utc)
    duration = (end_time - start_time).total_seconds()

    return {
        "ports": open_ports,
        "total_open": len(open_ports),
        "total_closed": closed_count,
        "total_filtered": filtered_count,
        "risk_level": risk_level,
        "risk_reason": risk_reason,
        "scan_duration": round(duration, 2),
        "resolved_ip": resolved_ip,
    }


def compute_risk_level(open_ports: List[dict]) -> Tuple[str, Optional[str]]:
    """
    Compute risk level based on open ports found.
    Returns (level, reason).
    """
    if not open_ports:
        return "low", None

    open_port_nums = {p["port"] for p in open_ports}

    # Critical ports that are almost always high risk
    critical_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 445: "SMB", 
        1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 
        5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB"
    }

    found_critical = []
    for p in open_ports:
        p_num = p["port"]
        if p_num in critical_ports:
            found_critical.append(critical_ports[p_num])

    if found_critical:
        reason = f"Critical Service(s) Open: {', '.join(found_critical)}"
        return "high", reason

    if len(open_ports) > 15:
        return "medium", "Large number of open ports found"
    
    if len(open_ports) > 5:
        return "medium", "Multiple ports open"

    return "low", None
