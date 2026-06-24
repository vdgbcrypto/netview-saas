#!/usr/bin/env python3
"""
Network Scanner Backend — Main Entry Point

Usage:
    python3 main.py [--subnet CIDR] [--output FILE] [--format json|table] [--no-snmp] [--no-icmp]

Examples:
    python3 main.py
    python3 main.py --subnet 192.168.1.0/24 --output scan.json
    python3 main.py --subnet 10.0.0.0/24 --format table
"""

import argparse
import json
import sys
import time
import os
from datetime import datetime

from scanner import (
    local_ip_and_subnet,
    mac_vendor_lookup,
    detect_device_type,
    SCAN_SUBNETS,
)
from arp_scan import arp_scan, arp_scan_fallback
from icmp_scan import icmp_scan
from snmp_scan import snmp_scan
from enrich import enrich_devices


def run_scan(subnets, use_icmp=True, use_arp=True, use_snmp=True, use_enrich=True):
    """Run a full network scan pipeline."""
    scan_start = time.time()
    print(f"[SCAN] Starting network scan at {datetime.now().isoformat()}")
    print(f"[SCAN] Target subnets: {', '.join(subnets)}")

    # ── Phase 1: ARP scan ──────────────────────────────────────────────
    arp_results = {}
    if use_arp:
        print("\n═══ Phase 1: ARP Scan ═══")
        arp_results = arp_scan(subnets)
        if not arp_results:
            print("[ARP] No ARP results from scapy; reading kernel ARP table")
            arp_results = arp_scan_fallback(subnets)

    # ── Phase 2: ICMP ping sweep ───────────────────────────────────────
    icmp_alive = []
    if use_icmp:
        print("\n═══ Phase 2: ICMP Ping Sweep ═══")
        icmp_alive = icmp_scan(subnets)

    # ── Phase 3: Merge discovered IPs ──────────────────────────────────
    all_ips = set(arp_results.keys()) | set(icmp_alive)
    # Always include gateway
    for subnet in subnets:
        gw = subnet.rsplit(".", 1)[0] + ".1"
        all_ips.add(gw)

    all_ips = sorted(all_ips)
    print(f"\n[MERGE] Total unique IPs to investigate: {len(all_ips)}")

    # ── Phase 4: SNMP queries ──────────────────────────────────────────
    snmp_results = {}
    if use_snmp and all_ips:
        print("\n═══ Phase 3: SNMP Queries ═══")
        snmp_results = snmp_scan(all_ips)

    # ── Phase 5: Hostname resolution & port probing ────────────────────
    enrich_results = {}
    if use_enrich and all_ips:
        print("\n═══ Phase 4: Hostname & Port Enrichment ═══")
        enrich_results = enrich_devices(all_ips)

    # ── Phase 6: Build device records ──────────────────────────────────
    print("\n═══ Building Device Records ═══")
    devices = []
    for ip in all_ips:
        mac = arp_results.get(ip, "00:00:00:00:00:00")
        snmp_data = snmp_results.get(ip, {})
        enrich_data = enrich_results.get(ip, {})

        hostname = enrich_data.get("hostname") or snmp_data.get("sysName")
        open_ports = enrich_data.get("open_ports", [])
        sys_descr = snmp_data.get("sysDescr", "")
        vendor = mac_vendor_lookup(mac) if mac != "00:00:00:00:00" else "Unknown"
        device_type = detect_device_type(mac, hostname, open_ports, sys_descr)

        device = {
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "vendor": vendor,
            "device_type": device_type,
            "open_ports": open_ports,
            "snmp": {
                "sysDescr": sys_descr,
                "sysName": snmp_data.get("sysName"),
                "sysObjectID": snmp_data.get("sysObjectID"),
                "sysUpTime": snmp_data.get("sysUpTime"),
                "community": snmp_data.get("snmp_community"),
            } if snmp_data else None,
            "source": (
                "arp+icmp" if ip in arp_results and ip in icmp_alive
                else "arp" if ip in arp_results
                else "icmp" if ip in icmp_alive
                else "inferred"
            ),
        }
        devices.append(device)

    scan_duration = time.time() - scan_start

    # ── Build output ───────────────────────────────────────────────────
    output = {
        "scan_info": {
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": round(scan_duration, 2),
            "subnets_scanned": subnets,
            "total_devices": len(devices),
            "arp_devices": len(arp_results),
            "icmp_devices": len(icmp_alive),
            "snmp_devices": len(snmp_results),
            "scanner_host": os.uname().nodename,
        },
        "devices": devices,
    }

    return output


def print_table(output):
    """Print devices as a formatted table."""
    devices = output["devices"]
    info = output["scan_info"]

    print(f"\n{'='*100}")
    print(f"  Network Scan Results — {info['timestamp']}")
    print(f"  Subnets: {', '.join(info['subnets_scanned'])}")
    print(f"  Duration: {info['duration_seconds']}s | Devices: {info['total_devices']}")
    print(f"{'='*100}")
    print(f"{'IP':<18} {'MAC':<20} {'Hostname':<25} {'Vendor':<18} {'Type':<18} {'Ports'}")
    print(f"{'-'*18} {'-'*20} {'-'*25} {'-'*18} {'-'*18} {'-'*30}")

    for d in devices:
        ports = ",".join(str(p) for p in d["open_ports"][:8]) if d["open_ports"] else "-"
        if len(d["open_ports"]) > 8:
            ports += f"...+{len(d['open_ports'])-8}"
        hn = d["hostname"][:24] if d["hostname"] else "-"
        print(f"{d['ip']:<18} {d['mac']:<20} {hn:<25} {d['vendor']:<18} {d['device_type']:<18} {ports}")

    print(f"{'='*100}")


def main():
    parser = argparse.ArgumentParser(description="Network Scanner Backend")
    parser.add_argument("--subnet", action="append", help="CIDR subnet to scan (repeatable)")
    parser.add_argument("--output", "-o", help="Output JSON file path")
    parser.add_argument("--format", choices=["json", "table", "both"], default="both")
    parser.add_argument("--no-icmp", action="store_true", help="Skip ICMP ping sweep")
    parser.add_argument("--no-snmp", action="store_true", help="Skip SNMP queries")
    parser.add_argument("--no-arp", action="store_true", help="Skip ARP scan")
    parser.add_argument("--no-enrich", action="store_true", help="Skip hostname/port enrichment")
    args = parser.parse_args()

    # Determine subnets
    if args.subnet:
        subnets = args.subnet
    else:
        _, detected = local_ip_and_subnet()
        subnets = [detected]
        print(f"[CONFIG] Auto-detected subnet: {detected}")

    # Run scan
    output = run_scan(
        subnets=subnets,
        use_icmp=not args.no_icmp,
        use_arp=not args.no_arp,
        use_snmp=not args.no_snmp,
        use_enrich=not args.no_enrich,
    )

    # Output
    if args.format in ("json", "both"):
        json_str = json.dumps(output, indent=2)
        if args.output:
            with open(args.output, "w") as f:
                f.write(json_str)
            print(f"\n[OUTPUT] JSON written to {args.output}")
        else:
            print(json_str)

    if args.format in ("table", "both"):
        print_table(output)

    return output


if __name__ == "__main__":
    main()
