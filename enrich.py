#!/usr/bin/env python3
"""Hostname resolution and port probing."""

import socket
import concurrent.futures
from scanner import HTTP_PROBE_TIMEOUT

# Common ports to check for device fingerprinting
COMMON_PORTS = [22, 80, 443, 445, 3389, 8080, 8443, 9100, 631, 161, 548, 5000, 5001, 8000, 8006, 8008, 8081, 9000, 9090, 9443, 3000, 3001, 5672, 2049, 111, 514, 53, 67, 68, 123, 137, 138, 139, 161, 162, 389, 636, 25, 110, 143, 993, 995, 587, 465]


def resolve_hostname(ip):
    """Reverse DNS lookup. Returns hostname or None."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


def check_port(ip, port):
    """Check if a TCP port is open. Returns port if open, None otherwise."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return port
    except (OSError, socket.error):
        pass
    return None


def probe_ports(ip, ports=None):
    """Scan common TCP ports on a host. Returns list of open ports."""
    if ports is None:
        ports = COMMON_PORTS
    open_ports = []
    for port in ports:
        if check_port(ip, port):
            open_ports.append(port)
    return open_ports


def resolve_and_probe(ip):
    """Resolve hostname and probe ports for a single IP. Returns (hostname, open_ports)."""
    hostname = resolve_hostname(ip)
    open_ports = probe_ports(ip)
    return hostname, open_ports


def enrich_devices(ips):
    """Parallel hostname resolution and port probing for all IPs."""
    results = {}
    print(f"[ENRICH] Resolving hostnames and probing ports for {len(ips)} hosts ...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(resolve_and_probe, ip): ip for ip in ips}
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            hostname, open_ports = future.result()
            results[ip] = {"hostname": hostname, "open_ports": open_ports}
            hn = hostname or "N/A"
            ports = ",".join(str(p) for p in open_ports) if open_ports else "none"
            print(f"[ENRICH] {ip}: hostname={hn}, ports=[{ports}]")
    return results
