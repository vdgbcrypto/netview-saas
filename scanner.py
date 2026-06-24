#!/usr/bin/env python3
"""
Network Scanner Backend Service
Discovers devices on the local network using ARP, ICMP, and SNMP.
Outputs structured JSON data.
"""

import json
import subprocess
import socket
import struct
import os
import sys
import concurrent.futures
import re
from datetime import datetime

# ── Configuration ──────────────────────────────────────────────────────────
SCAN_SUBNETS = ["10.0.0.0/24"]  # auto-detected or overridden via CLI
ICMP_TIMEOUT = 1       # seconds per ping
ICMP_CONCURRENCY = 50  # parallel pings
ARP_TIMEOUT = 3        # seconds for ARP scan
SNMP_COMMUNITIES = ["public", "private"]
SNMP_TIMEOUT = 2
SNMP_PORT = 161
HTTP_PROBE_TIMEOUT = 2

# ── Helpers ────────────────────────────────────────────────────────────────

def cidr_to_range(cidr):
    """Return (start_ip, end_ip, netmask) from CIDR string."""
    ip, bits = cidr.split("/")
    bits = int(bits)
    netmask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
    ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
    network = ip_int & netmask
    broadcast = network | (~netmask & 0xFFFFFFFF)
    return network, broadcast, netmask


def ip_list(cidr):
    """Generate IP strings for a /24 or larger CIDR (skips net/bcast)."""
    network, broadcast, _ = cidr_to_range(cidr)
    # Limit to reasonable size to avoid scanning huge subnets
    size = broadcast - network - 1
    if size > 4094:
        print(f"[WARN] {cidr} has {size} hosts; limiting to first /22 (1022 hosts)")
        broadcast = network + 1023
    return [socket.inet_ntoa(struct.pack("!I", i))
            for i in range(network + 1, broadcast)]


def local_ip_and_subnet():
    """Detect local IP and infer CIDR."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        # Assume /24 for now; refine with route table
        octets = ip.split(".")
        return ip, f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
    except OSError:
        return "127.0.0.1", "127.0.0.0/24"


def mac_vendor_lookup(mac):
    """Best-effort vendor from MAC OUI (local cache, no internet)."""
    # Common OUI prefixes for homelab environments
    OUI = {
        "00:50:56": "VMware", "00:0c:29": "VMware", "00:05:69": "VMware",
        "08:00:27": "VirtualBox", "0a:00:27": "VirtualBox",
        "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
        "e4:5f:01": "Raspberry Pi", "28:ee:52": "Raspberry Pi",
        "00:17:88": "Philips Hue", "ec:b5:fa": "Espressif",
        "dc:4f:22": "Espressif", "3c:61:05": "Espressif",
        "60:01:94": "Espressif", "24:0a:c4": "Espressif",
        "ac:cf:23": "Espressif", "4c:11:ae": "Espressif",
        "d8:3a:dd": "Espressif", "f4:cf:a2": "Espressif",
        "00:14:22": "Dell", "f8:bc:12": "Dell", "18:66:da": "Dell",
        "3c:97:0e": "Intel", "4c:ed:fb": "Intel",
        "00:1b:21": "Intel", "00:1c:c4": "Intel",
        "a4:5e:60": "Intel", "68:05:ca": "Intel",
        "00:0e:c4": "Cisco", "00:1a:a1": "Cisco", "00:1b:8f": "Cisco",
        "00:1c:58": "Cisco", "00:1d:71": "Cisco", "00:21:55": "Cisco",
        "00:22:55": "Cisco", "00:23:04": "Cisco", "00:24:14": "Cisco",
        "00:25:45": "Cisco", "00:26:0b": "Cisco",
        "f0:9f:c2": "Ubiquiti", "04:18:d6": "Ubiquiti", "24:a4:3c": "Ubiquiti",
        "68:d7:9a": "Ubiquiti", "70:a7:41": "Ubiquiti", "78:8a:20": "Ubiquiti",
        "74:83:c2": "Ubiquiti", "e0:63:da": "Ubiquiti",
        "00:11:22": "Synology", "00:11:32": "Synology",
        "00:50:43": "TP-Link", "50:c7:bf": "TP-Link", "ac:84:c6": "TP-Link",
        "c0:49:ef": "TP-Link", "d4:6e:0e": "TP-Link",
        "2c:f4:32": "TP-Link", "18:a6:f7": "TP-Link",
        "f6:b6:51": "TrueNAS/Local",  # Add local observed MACs
        "e6:ac:e8": "TrueNAS/Local",
    }
    prefix = mac[:8].lower()
    return OUI.get(prefix, "Unknown")


def detect_device_type(mac, hostname, open_ports, snmp_sysdesc):
    """Heuristic device type classification."""
    vendor = mac_vendor_lookup(mac)
    hn = hostname.lower() if hostname else ""

    # SNMP system description is most reliable
    if snmp_sysdesc:
        sd = snmp_sysdesc.lower()
        if "truenas" in sd or "freenas" in sd:
            return "NAS/Storage"
        if "pfsense" in sd or "opnsense" in sd:
            return "Firewall"
        if "esxi" in sd or "vmware" in sd:
            return "Hypervisor"
        if "linux" in sd:
            return "Linux Server"
        if "windows" in sd:
            return "Windows Host"
        if "switch" in sd or "cisco" in sd or "ubiquiti" in sd or "netgear" in sd:
            return "Network Equipment"
        if "printer" in sd:
            return "Printer"
        if "camera" in sd or "hikvision" in sd or "dahua" in sd:
            return "IP Camera"
        if "nas" in sd or "synology" in sd or "qnap" in sd:
            return "NAS/Storage"

    # Hostname-based heuristics
    for kw, dtype in [
        ("truenas", "NAS/Storage"), ("freenas", "NAS/Storage"),
        ("synology", "NAS/Storage"), ("qnap", "NAS/Storage"),
        ("pfsense", "Firewall"), ("opnsense", "Firewall"),
        ("router", "Network Equipment"), ("switch", "Network Equipment"),
        ("ap", "Access Point"), ("access-point", "Access Point"),
        ("pi", "Raspberry Pi"), ("raspberry", "Raspberry Pi"),
        ("desktop", "Desktop"), ("laptop", "Laptop"),
        ("printer", "Printer"), ("cam", "IP Camera"),
        ("nas", "NAS/Storage"), ("server", "Server"),
        ("vm", "Virtual Machine"), ("docker", "Container Host"),
        ("esxi", "Hypervisor"), ("proxmox", "Hypervisor"),
        ("phone", "Mobile"), ("iphone", "Mobile"), ("android", "Mobile"),
    ]:
        if kw in hn:
            return dtype

    # Vendor-based
    if vendor in ("VMware", "VirtualBox"):
        return "Virtual Machine"
    if vendor == "Raspberry Pi":
        return "Raspberry Pi"
    if vendor == "Ubiquiti":
        return "Network Equipment"
    if vendor in ("TP-Link", "Netgear"):
        return "Network Equipment"
    if vendor in ("Espressif",):
        return "IoT Device"
    if vendor == "Intel":
        return "Computer"

    # Port-based
    if 9100 in open_ports:
        return "Printer"
    if {80, 443, 8080, 8443} & set(open_ports):
        return "Network Equipment"  # Likely has web UI

    return "Unknown"
