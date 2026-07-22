#!/usr/bin/env python3
"""
Port Scanner
------------
A real TCP connect-scan port scanner with multithreading, common-service
identification, and banner grabbing.

IMPORTANT: Only scan hosts you own or have explicit written authorization
to scan. Scanning systems without permission may be illegal in your
jurisdiction (e.g. under the Computer Fraud and Abuse Act in the US, or
equivalent laws elsewhere).

Usage:
    python port_scanner.py 127.0.0.1
    python port_scanner.py 127.0.0.1 --ports 1-1024
    python port_scanner.py scanme.example.com --ports 22,80,443 --threads 100
"""

import argparse
import socket
import sys
import threading
import queue
import time
from datetime import datetime


# Common ports and the services usually running on them.
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1723: "PPTP", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}

print_lock = threading.Lock()


def parse_ports(port_spec: str) -> list:
    """
    Parse a port specification into a sorted list of unique ints.
    Supports: '80', '80,443,8080', '1-1024', or a mix: '22,80,1000-1010'
    """
    ports = set()
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            start, end = int(start), int(end)
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: {part}")
            ports.update(range(start, end + 1))
        elif part:
            p = int(part)
            if p < 1 or p > 65535:
                raise ValueError(f"Invalid port: {p}")
            ports.add(p)
    return sorted(ports)


def resolve_target(target: str) -> str:
    """Resolve a hostname to an IP address. Raises socket.gaierror if it fails."""
    return socket.gethostbyname(target)


def grab_banner(sock: socket.socket) -> str:
    """Attempt to read a service banner from an already-connected socket."""
    try:
        sock.settimeout(1.0)
        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner[:100] if banner else ""
    except (socket.timeout, ConnectionResetError, OSError):
        return ""


def scan_port(ip: str, port: int, timeout: float, results: list, grab_banners: bool):
    """Attempt a TCP connect to a single port. Records the result if open."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            banner = grab_banner(sock) if grab_banners else ""
            with print_lock:
                results.append({"port": port, "service": service, "banner": banner})
    except (socket.timeout, OSError):
        pass
    finally:
        sock.close()


def worker(ip: str, port_queue: queue.Queue, timeout: float, results: list, grab_banners: bool):
    while True:
        try:
            port = port_queue.get_nowait()
        except queue.Empty:
            return
        scan_port(ip, port, timeout, results, grab_banners)
        port_queue.task_done()


def run_scan(target: str, ports: list, thread_count: int, timeout: float, grab_banners: bool) -> dict:
    """Run a multithreaded scan and return structured results."""
    try:
        ip = resolve_target(target)
    except socket.gaierror as e:
        raise ValueError(f"Could not resolve host '{target}': {e}")

    port_queue = queue.Queue()
    for port in ports:
        port_queue.put(port)

    results = []
    threads = []
    start_time = time.time()

    for _ in range(min(thread_count, len(ports)) or 1):
        t = threading.Thread(target=worker, args=(ip, port_queue, timeout, results, grab_banners))
        t.daemon = True
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    elapsed = time.time() - start_time
    results.sort(key=lambda r: r["port"])

    return {
        "target": target,
        "ip": ip,
        "ports_scanned": len(ports),
        "open_ports": results,
        "elapsed_seconds": round(elapsed, 2),
        "timestamp": datetime.now().isoformat(),
    }


def print_report(scan_result: dict):
    print("\n" + "=" * 60)
    print(f"  PORT SCAN REPORT")
    print("=" * 60)
    print(f"  Target       : {scan_result['target']} ({scan_result['ip']})")
    print(f"  Ports scanned: {scan_result['ports_scanned']}")
    print(f"  Time taken   : {scan_result['elapsed_seconds']}s")
    print(f"  Open ports   : {len(scan_result['open_ports'])}")
    print("-" * 60)

    if not scan_result["open_ports"]:
        print("  No open ports found in the scanned range.")
    else:
        print(f"  {'PORT':<8}{'STATE':<8}{'SERVICE':<15}{'BANNER'}")
        for r in scan_result["open_ports"]:
            banner = r["banner"] if r["banner"] else "-"
            print(f"  {r['port']:<8}{'open':<8}{r['service']:<15}{banner}")
    print("=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Multithreaded TCP port scanner (authorized use only)"
    )
    parser.add_argument("target", help="Hostname or IP address to scan")
    parser.add_argument("--ports", default="1-1024",
                         help="Ports to scan: '80', '1-1024', or '22,80,443' (default: 1-1024)")
    parser.add_argument("--threads", type=int, default=100, help="Number of worker threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=0.5, help="Per-port timeout in seconds (default: 0.5)")
    parser.add_argument("--banners", action="store_true", help="Attempt to grab service banners on open ports")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of a formatted report")
    args = parser.parse_args()

    print("NOTE: Only scan systems you own or are explicitly authorized to test.")

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"[!] {e}")
        sys.exit(1)

    try:
        result = run_scan(args.target, ports, args.threads, args.timeout, args.banners)
    except ValueError as e:
        print(f"[!] {e}")
        sys.exit(1)

    if args.json:
        import json
        print(json.dumps(result, indent=2))
    else:
        print_report(result)


if __name__ == "__main__":
    main()
