# Network Scanner Backend

Discovers devices on the local network using ARP scanning, ICMP ping sweeps,
SNMP queries, and TCP port probing. Outputs structured JSON data.

## Architecture

```
main.py          — CLI entry point, orchestrates the scan pipeline
scanner.py       — Core utilities (CIDR math, vendor lookup, device classification)
arp_scan.py      — ARP scanning via scapy (with /proc/net/arp fallback)
icmp_scan.py     — Parallel ICMP ping sweep
snmp_scan.py     — SNMPv1/v2c queries (sysDescr, sysName, sysObjectID, sysUpTime)
enrich.py        — Reverse DNS resolution and TCP port probing
server.py        — HTTP API server for REST access to scan results
```

## Scan Pipeline

1. **ARP Scan** — Sends ARP requests to discover MAC addresses (requires root/cap_net_raw;
   falls back to reading `/proc/net/arp`)
2. **ICMP Sweep** — Parallel ping to find alive hosts across all target subnets
3. **SNMP Queries** — Attempts SNMPv1/v2c GET on discovered hosts (communities: public, private)
4. **Enrichment** — Reverse DNS lookups and TCP port probing (50+ common ports)
5. **Classification** — Heuristic device type detection based on ports, vendor, SNMP data, hostname

## Usage

```bash
# Auto-detect subnet and scan
uv run python3 main.py

# Scan specific subnets
uv run python3 main.py --subnet 192.168.1.0/24 --subnet 10.0.0.0/24

# Output to file
uv run python3 main.py --output scan.json --format json

# Table output only
uv run python3 main.py --format table

# Skip SNMP or ICMP
uv run python3 main.py --no-snmp
uv run python3 main.py --no-icmp
```

## HTTP API

```bash
# Start the API server
uv run python3 server.py --port 8080

# Run a scan
curl http://localhost:8080/scan

# List all devices
curl http://localhost:8080/devices

# Filter by device type
curl http://localhost:8080/devices?type=Network%20Equipment

# Get specific device
curl http://localhost:8080/device/192.168.1.1
```

## Output Format

```json
{
  "scan_info": {
    "timestamp": "2026-06-23T11:50:01",
    "duration_seconds": 75.29,
    "subnets_scanned": ["172.16.2.0/24", "192.168.1.0/24"],
    "total_devices": 32,
    "arp_devices": 1,
    "icmp_devices": 32,
    "snmp_devices": 0
  },
  "devices": [
    {
      "ip": "192.168.1.1",
      "mac": "00:00:00:00:00:00",
      "hostname": null,
      "vendor": "Unknown",
      "device_type": "Network Equipment",
      "open_ports": [80, 443, 53],
      "snmp": null,
      "source": "icmp"
    }
  ]
}
```

## Requirements

- Python 3.12+
- scapy 2.7+ (for ARP scanning)
- Root or `CAP_NET_RAW` for full ARP scanning (ICMP works without root)

## Notes

- MAC addresses for remote subnets (routed) will show as `00:00:00:00:00:00` since ARP
  only works on the local broadcast domain. For full MAC collection, run on each subnet
  or use the VM/host with `arp-scan`/`nmap -sn`.
- SNMP requires devices to have SNMP enabled with community strings "public" or "private".
- The scanner auto-limits subnets larger than /22 to avoid excessive scan times.
