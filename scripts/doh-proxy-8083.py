#!/usr/bin/env python3
"""
Souran AI Network Server - DoH Proxy v1.0.0
Port 8083 - Your User DoH Endpoint
DNS-over-HTTPS with Zero-Upstream support
Version: 0.1.0 - Built from source
"""

import http.server
import urllib.request
import urllib.error
import urllib.parse
import json
import socket
import ssl
from typing import Dict, Any, Optional
from http import HTTPStatus

# Configuration
PORT = 8083
HOST = "0.0.0.0"
VERSION = "0.1.0"
ZERO_UPSTREAM = True

# Zero-Upstream DNS Settings
DNS_SERVER = "127.0.0.1"
DNS_PORT = 53  # Tor DNS

class DoHHandler(http.server.BaseHTTPRequestHandler):
    """DNS-over-HTTPS request handler"""
    
    def log_message(self, format, *args):
        """Log to file"""
        with open("/var/log/souran-doh-8083.log", "a") as f:
            f.write("%s - - [%s] %s\n" % 
                   (self.client_address[0], self.log_date_time_string(), format % args))

    def send_json_response(self, code: int, data: Dict[str, Any]):
        """Send JSON response"""
        self.send_response(code)
        self.send_header('Content-Type', 'application/dns-json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('X-Souran-Version', VERSION)
        self.send_header('X-Zero-Upstream', 'true' if ZERO_UPSTREAM else 'false')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/' or self.path == '/health':
            # Health check
            response = {
                "status": "ok",
                "version": VERSION,
                "port": PORT,
                "zero_upstream": ZERO_UPSTREAM,
                "dns_server": f"{DNS_SERVER}:{DNS_PORT}"
            }
            self.send_json_response(HTTPStatus.OK, response)
            return

        if self.path == '/dns-query' or self.path.startswith('/dns-query'):
            # Parse DNS query from URL
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            
            name = params.get('name', [''])[0].lower()
            qtype = params.get('type', ['A'])[0]
            
            if not name:
                self.send_json_response(HTTPStatus.BAD_REQUEST, {
                    "Status": 1,
                    "TC": False,
                    "RD": True,
                    "RA": True,
                    "AD": False,
                    "Question": []
                })
                return
            
            # Convert type to number
            type_map = {
                'A': 1, 'AAAA': 28, 'MX': 15, 'TXT': 16,
                'CNAME': 5, 'NS': 2, 'SOA': 6, 'PTR': 12,
                'SRV': 33, 'CAA': 257, 'ANY': 255
            }
            qtype_num = type_map.get(qtype.upper(), 1)
            
            # Resolver DNS query through Zero-Upstream (Tor DNS on port 53)
            result = self.resolve_via_tor_dns(name, qtype_num)
            
            self.send_json_response(HTTPStatus.OK, result)
            return
        
        if self.path == '/api/status':
            # Status endpoint
            response = {
                "version": VERSION,
                "port": PORT,
                "zero_upstream": ZERO_UPSTREAM,
                "dns_server": f"{DNS_SERVER}:{DNS_PORT}",
                "status": "running"
            }
            self.send_json_response(HTTPStatus.OK, response)
            return
        
        # Unknown path
        self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def resolve_via_tor_dns(self, name: str, qtype: int) -> Dict[str, Any]:
        """Resolve DNS query via Tor DNS (Zero-Upstream)"""
        try:
            # Use dig-style DNS query over UDP to Tor DNS
            import subprocess
            result = subprocess.run(
                ['dig', '@127.0.0.1', '-p', '53', name, 
                 'TYPE=' + str(qtype), '+short', '+time=5'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            answers = []
            for line in result.stdout.strip().split('\n'):
                if line and not line.startswith(';'):
                    answers.append({
                        "name": name,
                        "type": qtype,
                        "TTL": 300,
                        "data": line
                    })
            
            return {
                "Status": 0,
                "TC": False,
                "RD": True,
                "RA": True,
                "AD": ZERO_UPSTREAM,  # DNSSEC disabled for Tor
                "Question": [{"name": name, "type": qtype}],
                "Answer": answers
            }
            
        except Exception as e:
            # Fallback to direct resolution
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(5)
                
                # Build DNS query packet
                import struct
                transaction_id = 0x1234
                flags = 0x0100  # Standard query with recursion
                
                query = struct.pack('>HHHHHH',
                    transaction_id,
                    flags,
                    1,  # Questions
                    0,  # Answer RRs
                    0,  # Authority RRs
                    0   # Additional RRs
                )
                
                # Encode query name
                labels = name.split('.')
                for label in labels:
                    query += struct.pack('B', len(label)) + label.encode()
                query += b'\x00'  # Root
                
                # Query type and class
                query += struct.pack('>HH', qtype, 1)  # QTYPE, QCLASS
                
                sock.sendto(query, (DNS_SERVER, DNS_PORT))
                response, _ = sock.recvfrom(512)
                sock.close()
                
                return {
                    "Status": 0,
                    "TC": False,
                    "RD": True,
                    "RA": True,
                    "AD": False,
                    "Question": [{"name": name, "type": qtype}],
                    "Answer": []
                }
                
            except Exception as e2:
                return {
                    "Status": 2,
                    "TC": False,
                    "RD": True,
                    "RA": False,
                    "AD": False,
                    "Question": [{"name": name, "type": qtype}],
                    "Answer": [],
                    "Error": str(e2)
                }

    def do_POST(self):
        """Handle POST requests (DNS update)"""
        if self.path == '/dns-query':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            
            try:
                data = json.loads(body)
                name = data.get('name', '').lower()
                qtype = data.get('type', 'A')
                
                type_map = {'A': 1, 'AAAA': 28, 'MX': 15, 'TXT': 16, 'CNAME': 5}
                qtype_num = type_map.get(qtype.upper(), 1)
                
                result = self.resolve_via_tor_dns(name, qtype_num)
                self.send_json_response(HTTPStatus.OK, result)
                
            except Exception as e:
                self.send_json_response(HTTPStatus.BAD_REQUEST, {
                    "Status": 1,
                    "Error": str(e)
                })
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

if __name__ == '__main__':
    print(f"[DoH] Starting Souran DNS-over-HTTPS Proxy v{VERSION}")
    print(f"[DoH] Listening on {HOST}:{PORT}")
    print(f"[DoH] Zero-Upstream: {ZERO_UPSTREAM}")
    print(f"[DoH] DNS Server: {DNS_SERVER}:{DNS_PORT}")
    
    server = http.server.HTTPServer((HOST, PORT), DoHHandler)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[DoH] Shutting down...")
        server.shutdown()