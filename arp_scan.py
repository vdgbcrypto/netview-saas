#!/usr/bin/env python3
"""ARP scanner using scapy."""

import sys
import json
import time
from scanner import ARP_TIMEOUT, mac_vendor_lookup

def arp_scan(subnets):
    """Send ARP requests to all IPs in subnets, return {ip: mac} dict."""
    try:
        from scapy.all import ARP, Ether, srp, conf
        conf.verb = 0  # suppress scapy output
    except ImportError:
        print("[WARN] scapy not available, skipping ARP scan", file=sys.stderr)
        return {}

    results = {}
    for subnet in subnets:
        print(f"[ARP] Scanning {subnet} ...")
        try:
            # Build ARP request packet
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
                timeout=ARP_TIMEOUT,
                retry=1,
                verbose=False,
            )
            for sent, received in ans:
                ip = received.psrc
                mac = received.hwsrc.lower()
                results[ip] = mac
                print(f"[ARP] {ip} -> {mac} ({mac_vendor_lookup(mac)})")
        except PermissionError:
            print("[WARN] ARP scan requires root/cap_net_raw; trying subprocess fallback")
            return arp_scan_fallback(subnets)
        except Exception as e:
            print(f"[ERROR] ARP scan failed for {subnet}: {e}", file=sys.stderr)

    return results


def arp_scan_fallback(subnets):
    """Fallback: read kernel ARP table after pinging broadcast."""
    results = {}
    try:
        with open("/proc/net/arp") as f:
            lines = f.readlines()[1:]  # skip header
        for line in lines:
            parts = line.split()
            if len(parts) >= 4:
                ip = parts[0]
                mac = parts[3].lower()
                if mac != "00:00:00:00:00:00":
                    results[ip] = mac
    except Exception as e:
        print(f"[ERROR] ARP fallback failed: {e}", file=sys.stderr)
    return results
