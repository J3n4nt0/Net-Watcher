"""
NetWatcher - Network diagnostic toolbox.
Pure stdlib + subprocess calls out to system ping/traceroute so this runs
on any Linux box without extra network-capture privileges.
"""
import ipaddress
import platform
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

IS_WINDOWS = platform.system().lower() == "windows"


def ping(host: str, timeout_s: int = 1) -> dict:
    """Ping a single host, return status + latency."""
    start = time.time()
    try:
        if IS_WINDOWS:
            cmd = ["ping", "-n", "1", "-w", str(timeout_s * 1000), host]
        else:
            cmd = ["ping", "-c", "1", "-W", str(timeout_s), host]
        resp = subprocess.run(cmd, capture_output=True, timeout=timeout_s + 1, text=True)
        elapsed_ms = round((time.time() - start) * 1000, 1)
        is_alive = resp.returncode == 0

        latency = elapsed_ms
        m = re.search(r"time[=<]([\d.]+)", resp.stdout)
        if m:
            latency = float(m.group(1))

        return {
            "ip": host,
            "status": "UP" if is_alive else "DOWN",
            "alive": is_alive,
            "latency_ms": latency if is_alive else None,
        }
    except subprocess.TimeoutExpired:
        return {"ip": host, "status": "DOWN", "alive": False, "latency_ms": None}
    except Exception:
        return {"ip": host, "status": "ERROR", "alive": False, "latency_ms": None}


def sweep(target_ips: list[str], max_workers: int = 200) -> dict:
    alive, down = [], []
    details = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(ping, ip): ip for ip in target_ips}
        for future in as_completed(futures):
            result = future.result()
            details.append(result)
            (alive if result["alive"] else down).append(result["ip"])
    return {"alive": alive, "down": down, "total": len(target_ips), "details": details}


def resolve_targets(subnet: str | None, ips: str | None) -> list[str]:
    if subnet:
        network = ipaddress.ip_network(subnet, strict=False)
        return [str(h) for h in network.hosts()]
    if ips:
        return [ip.strip() for ip in ips.split(",") if ip.strip()]
    return ["127.0.0.1", "8.8.8.8", "1.1.1.1"]


COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 161: "SNMP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}


def scan_port(host: str, port: int, timeout_s: float = 0.5) -> dict:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout_s)
            result = s.connect_ex((host, port))
            open_ = result == 0
            return {
                "port": port,
                "open": open_,
                "service": COMMON_PORTS.get(port, "unknown"),
            }
    except Exception:
        return {"port": port, "open": False, "service": COMMON_PORTS.get(port, "unknown")}


def port_scan(host: str, ports: list[int] | None = None, max_workers: int = 50) -> dict:
    ports = ports or list(COMMON_PORTS.keys())
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(scan_port, host, p): p for p in ports}
        for future in as_completed(futures):
            r = future.result()
            if r["open"]:
                open_ports.append(r)
    open_ports.sort(key=lambda r: r["port"])
    return {"host": host, "scanned": len(ports), "open_ports": open_ports}


def dns_lookup(host: str) -> dict:
    try:
        ip = socket.gethostbyname(host)
        try:
            reverse = socket.gethostbyaddr(ip)[0]
        except Exception:
            reverse = None
        return {"query": host, "ip": ip, "reverse_dns": reverse, "ok": True}
    except socket.gaierror as e:
        return {"query": host, "ok": False, "error": str(e)}


def traceroute(host: str, max_hops: int = 20) -> dict:
    try:
        if IS_WINDOWS:
            cmd = ["tracert", "-h", str(max_hops), "-w", "1000", host]
        else:
            cmd = ["traceroute", "-m", str(max_hops), "-w", "1", host]
        resp = subprocess.run(cmd, capture_output=True, timeout=max_hops * 2 + 5, text=True)
        return {"host": host, "output": resp.stdout or resp.stderr, "ok": resp.returncode == 0}
    except FileNotFoundError:
        return {"host": host, "ok": False, "error": "traceroute/tracert not installed on this system"}
    except subprocess.TimeoutExpired:
        return {"host": host, "ok": False, "error": "traceroute timed out"}


def subnet_info(cidr: str) -> dict:
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = list(net.hosts())
    return {
        "cidr": str(net),
        "network_address": str(net.network_address),
        "broadcast_address": str(net.broadcast_address) if net.version == 4 else None,
        "netmask": str(net.netmask) if net.version == 4 else None,
        "num_addresses": net.num_addresses,
        "usable_hosts": len(hosts),
        "first_usable": str(hosts[0]) if hosts else None,
        "last_usable": str(hosts[-1]) if hosts else None,
        "is_private": net.is_private,
    }
