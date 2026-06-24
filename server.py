#!/usr/bin/env python3
"""
Simple HTTP API server for the network scanner.
Serves scan results via REST endpoints.

Usage:
    python3 server.py [--port 8080]

Endpoints:
    GET /          - API info
    GET /scan      - Run a new scan and return results
    GET /devices   - List devices from last scan
    GET /device/<ip> - Get details for a specific device
"""

import argparse
import json
import os
import sys
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Import scanner
from main import run_scan
from scanner import local_ip_and_subnet

# Global state
last_scan = None
scan_lock = threading.Lock()


class ScannerHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the scanner API."""

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        params = parse_qs(parsed.query)

        if path == "" or path == "/":
            self._respond(200, {
                "service": "Network Scanner API",
                "version": "1.0.0",
                "endpoints": {
                    "/scan": "Run a new scan (GET or POST)",
                    "/devices": "List all devices from last scan",
                    "/device/<ip>": "Get device details",
                },
            })

        elif path == "/scan":
            subnets = params.get("subnet", None)
            if not subnets:
                _, detected = local_ip_and_subnet()
                subnets = [detected]

            fmt = params.get("format", ["json"])[0]
            use_icmp = "no_icmp" not in params
            use_snmp = "no_snmp" not in params

            try:
                result = run_scan(
                    subnets=subnets,
                    use_icmp=use_icmp,
                    use_arp=True,
                    use_snmp=use_snmp,
                    use_enrich=True,
                )
                global last_scan
                with scan_lock:
                    last_scan = result

                if fmt == "json":
                    self._respond(200, result)
                else:
                    self._respond(200, result)  # Always JSON for API
            except Exception as e:
                self._respond(500, {"error": str(e)})

        elif path == "/devices":
            with scan_lock:
                if last_scan is None:
                    self._respond(404, {"error": "No scan has been run yet. GET /scan first."})
                    return
                devices = last_scan["devices"]
                # Filter by type if requested
                dtype = params.get("type", [None])[0]
                if dtype:
                    devices = [d for d in devices if d["device_type"].lower() == dtype.lower()]
                self._respond(200, {
                    "total": len(devices),
                    "devices": devices,
                })

        elif path.startswith("/device/"):
            ip = path[len("/device/"):]
            with scan_lock:
                if last_scan is None:
                    self._respond(404, {"error": "No scan has been run yet."})
                    return
                for d in last_scan["devices"]:
                    if d["ip"] == ip:
                        self._respond(200, d)
                        return
                self._respond(404, {"error": f"Device {ip} not found"})

        else:
            self._respond(404, {"error": "Not found"})

    def _respond(self, code, data):
        body = json.dumps(data, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser(description="Network Scanner HTTP API")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--host", default="0.0.0.0")
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), ScannerHandler)
    print(f"[SERVER] Network Scanner API running on {args.host}:{args.port}")
    print(f"[SERVER] Endpoints: /scan, /devices, /device/<ip>")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down")
        server.server_close()


if __name__ == "__main__":
    main()
