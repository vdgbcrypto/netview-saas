#!/usr/bin/env python3
"""ICMP ping scanner — fast parallel sweep."""

import subprocess
import sys
import concurrent.futures
from scanner import ICMP_TIMEOUT, ICMP_CONCURRENCY, ip_list

def ping_host(ip):
    """Ping a single host. Returns ip if alive, None if not."""
    try:
        r = subprocess.run(
            ["ping", "-c", "1", "-W", str(ICMP_TIMEOUT), ip],
            capture_output=True,
            timeout=ICMP_TIMEOUT + 2,
        )
        if r.returncode == 0:
            return ip
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def icmp_scan(subnets):
    """Parallel ICMP ping sweep. Returns list of alive IPs."""
    all_ips = []
    for subnet in subnets:
        all_ips.extend(ip_list(subnet))

    print(f"[ICMP] Pinging {len(all_ips)} hosts ({ICMP_CONCURRENCY} parallel) ...")
    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=ICMP_CONCURRENCY) as ex:
        futures = {ex.submit(ping_host, ip): ip for ip in all_ips}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                alive.append(result)
                print(f"[ICMP] {result} is alive")

    print(f"[ICMP] {len(alive)} hosts responded to ping")
    return alive
