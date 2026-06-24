#!/usr/bin/env python3
"""SNMP scanner — queries sysDescr, sysName, sysObjectID."""

import socket
import sys
import concurrent.futures
from scanner import SNMP_COMMUNITIES, SNMP_TIMEOUT, SNMP_PORT

# Minimal SNMPv1/v2c GET builder
def snmp_get(oid, ip, community, port=SNMP_PORT, timeout=SNMP_TIMEOUT):
    """Send a single SNMP GET request. Returns value string or None."""
    try:
        # Build SNMPv1 GETREQUEST PDU
        # OID to bytes
        oid_parts = [int(x) for x in oid.split(".")]
        # First two arcs are compressed: 1.3 -> 43 (0x2b)
        oid_bytes = bytes([43])  # 1.3
        for part in oid_parts[2:]:
            if part < 128:
                oid_bytes += bytes([part])
            else:
                # multi-byte encoding
                b = []
                v = part
                while v:
                    b.insert(0, (v & 0x7F) | 0x80)
                    v >>= 7
                b[-1] &= 0x7F
                oid_bytes += bytes(b)

        # Build VarBind: SEQUENCE { OID, NULL }
        oid_tlv = b'\x06' + bytes([len(oid_bytes)]) + oid_bytes
        null_val = b'\x05\x00'
        varbind = b'\x30' + bytes([len(oid_tlv) + len(null_val)]) + oid_tlv + null_val
        varbind_seq = b'\x30' + bytes([len(varbind)]) + varbind

        # PDU: GETREQUEST
        request_id = b'\x01\x00'  # request-id = 0
        error_status = b'\x02\x00\x00'  # error-status = 0
        error_index = b'\x02\x00\x00'   # error-index = 0
        pdu_content = request_id + error_status + error_index + varbind_seq
        pdu = b'\xa0' + bytes([len(pdu_content)]) + pdu_content  # GETREQUEST tag

        # SNMP message
        version = b'\x02\x01\x00'  # v1
        comm = b'\x04' + bytes([len(community)]) + community.encode()
        msg_content = version + comm + pdu
        msg = b'\x30' + bytes([len(msg_content)]) + msg_content

        # Send via UDP
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(msg, (ip, port))
        data, _ = sock.recvfrom(4096)
        sock.close()

        # Parse response — find the value after the OID in the response
        # Look for NULL (0x05 0x00) or OCTET STRING (0x04 len ...) after OID
        idx = data.find(oid_bytes)
        if idx == -1:
            return None
        val_start = idx + len(oid_bytes)
        # Skip the OID TLV header
        tag = data[val_start]
        if tag == 0x05:  # NULL
            return None
        if tag == 0x04:  # OCTET STRING
            length = data[val_start + 1]
            return data[val_start + 2:val_start + 2 + length].decode("utf-8", errors="replace")
        if tag == 0x02:  # INTEGER
            length = data[val_start + 1]
            val = 0
            for b in data[val_start + 2:val_start + 2 + length]:
                val = (val << 8) | b
            return str(val)
        return None

    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    except Exception as e:
        return None


def snmp_query_device(ip):
    """Try SNMP queries on a device. Returns dict with sysDescr, sysName, etc."""
    OIDS = {
        "sysDescr":    "1.3.6.1.2.1.1.1.0",
        "sysName":     "1.3.6.1.2.1.1.5.0",
        "sysObjectID": "1.3.6.1.2.1.1.2.0",
        "sysUpTime":   "1.3.6.1.2.1.1.3.0",
    }
    for community in SNMP_COMMUNITIES:
        result = {}
        for key, oid in OIDS.items():
            val = snmp_get(oid, ip, community)
            if val is not None:
                result[key] = val
        if result:
            result["snmp_community"] = community
            print(f"[SNMP] {ip}: {result.get('sysName', '?')} - {result.get('sysDescr', '')[:60]}")
            return result
    return None


def snmp_scan(ips):
    """Scan list of IPs for SNMP. Returns {ip: snmp_data}."""
    results = {}
    print(f"[SNMP] Querying {len(ips)} hosts ...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(snmp_query_device, ip): ip for ip in ips}
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            data = future.result()
            if data:
                results[ip] = data
    print(f"[SNMP] {len(results)} hosts responded to SNMP")
    return results
