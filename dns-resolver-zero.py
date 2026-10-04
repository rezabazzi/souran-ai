#!/usr/bin/env python3
"""
Souran AI Network Server - Zero Upstream DNS Resolver
Python-based DNS resolver with no forwarders
Version: 1.0.0
"""

import socket
import struct
import sys
from typing import Optional, Tuple

class DNSResolver:
    """DNS resolver with iterative resolution - zero upstream"""
    
    def __init__(self):
        self.cache = {}
        self.root_servers = self.load_root_hints()
        
    def load_root_hints(self) -> list:
        """Load root server IPs from root.hints file"""
        root_servers = []
        try:
            with open('/etc/unbound/root.hints', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('.') or line.startswith(';'):
                        continue
                    parts = line.split()
                    if len(parts) >= 4 and parts[2] == 'IN':
                        if parts[3] == 'A':
                            root_servers.append((parts[0].rstrip('.'), parts[4]))
                        elif parts[3] == 'AAAA':
                            root_servers.append((parts[0].rstrip('.'), parts[4]))
        except Exception as e:
            print(f"Error loading root hints: {e}", file=sys.stderr)
        return root_servers[:13]  # Ensure we have 13 root servers
    
    def create_query(self, domain: str, qtype: int = 1) -> bytes:
        """Create a DNS query packet"""
        # Transaction ID
        tid = 0x1234
        # Flags: standard query
        flags = 0x0100
        # Questions: 1, Answers: 0, Authority: 0, Additional: 0
        hdr = struct.pack('>HHHHHH', tid, flags, 1, 0, 0, 0)
        
        # Build domain name
        qname = b''
        for part in domain.split('.'):
            qname += bytes([len(part)]) + part.encode()
        qname += b'\x00'
        
        # Question: QTYPE (A=1), QCLASS (IN=1)
        question = qname + struct.pack('>HH', qtype, 1)
        
        return hdr + question
    
    def parse_response(self, data: bytes) -> Tuple[int, list, list]:
        """Parse DNS response"""
        # Parse header
        tid, flags, qdcount, ancount, nscount, arcount = struct.unpack('>HHHHHH', data[:12])
        
        # Check for errors
        rcode = flags & 0x0F
        if rcode != 0:
            return rcode, [], []
        
        # Parse answers
        pos = 12
        answers = []
        
        # Skip questions
        while pos < len(data):
            if data[pos] == 0:
                pos += 1
                break
            label_len = data[pos]
            pos += 1 + label_len
            pos += 4  # type and class
        
        for _ in range(ancount):
            if pos + 10 > len(data):
                break
            
            name_len = data[pos]
            if name_len == 0xC0:  # Compressed name
                pos += 2
            else:
                pos += 1 + name_len
            
            qtype, qclass, ttl, rdlength = struct.unpack('>HHIH', data[pos:pos+10])
            pos += 10
            
            if qtype == 1:  # A record
                addr = '.'.join(str(b) for b in data[pos:pos+4])
                answers.append(addr)
            elif qtype == 28:  # AAAA record
                addr_bytes = data[pos:pos+16]
                addr = ':'.join(f'{addr_bytes[i]*16+addr_bytes[i+1]:02x}' for i in range(0, 16, 2))
                answers.append(addr)
            elif qtype == 2:  # NS record
                # Parse NS name
                pos += rdlength
            else:
                pos += rdlength
        
        # Parse additional section for IPs
        additional = []
        for _ in range(arcount):
            # Similar parsing for additional records
            pass
        
        return 0, answers, additional
    
    def query(self, domain: str) -> Optional[str]:
        """Query a domain using iterative resolution"""
        # Check cache first
        if domain in self.cache:
            return self.cache[domain]
        
        # Start with root servers
        servers = [(name, ip) for name, ip in self.root_servers if '.' in name]
        
        # Build query
        query = self.create_query(domain)
        
        # Try each root server
        for server_name, server_ip in servers[:3]:  # Try first 3 root servers
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                sock.sendto(query, (server_ip, 53))
                
                response, _ = sock.recvfrom(512)
                rcode, answers, additional = self.parse_response(response)
                
                if rcode == 0 and answers:
                    result = answers[0]
                    self.cache[domain] = result
                    sock.close()
                    return result
                
                sock.close()
            except socket.timeout:
                continue
            except Exception as e:
                continue
        
        return None

def main():
    """Main function - simple DNS server"""
    resolver = DNSResolver()
    
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 53))
    
    print("Souran DNS Server running on port 53 (zero upstream)", file=sys.stderr)
    
    while True:
        try:
            data, addr = sock.recvfrom(512)
            
            # Parse query
            tid = struct.unpack('>H', data[:2])[0]
            
            # Extract domain name
            domain = ''
            pos = 12
            while pos < len(data):
                if data[pos] == 0:
                    break
                label_len = data[pos]
                pos += 1
                domain += data[pos:pos+label_len].decode() + '.'
                pos += label_len
            
            domain = domain.rstrip('.')
            
            # Query the domain
            answer = resolver.query(domain)
            
            # Build response
            if answer:
                # Success response
                response = struct.pack('>HHHHHH', tid, 0x8180, 1, 1, 0, 0)
                response += b'\x00'  # End of name
                response += struct.pack('>HHIH', 1, 1, 300, 4)
                
                # Add A record
                parts = answer.split('.')
                response += struct.pack('>I', int(parts[0]) << 24 | int(parts[1]) << 16 | int(parts[2]) << 8 | int(parts[3]))
            else:
                # SERVFAIL response
                response = struct.pack('>HHHHHH', tid, 0x8182, 1, 0, 0, 0)
                response += b'\x00'
            
            sock.sendto(response, addr)
            
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)

if __name__ == '__main__':
    main()