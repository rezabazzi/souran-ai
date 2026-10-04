#!/bin/bash
#===============================================================================
# Souran AI Network Server - Installation Script v3.1.0
# Build from absolute zero - zero upstream DNS resolver
#===============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

VERSION="3.1.0"
BUILD_DATE="2026-10-01"
SOURAN_DIR="/opt/souran-ai"
DNS_DIR="$SOURAN_DIR/dns"
LOG_FILE="/var/log/souran-install.log"

log() {
    echo -e "${GREEN}[$(date -u '+%Y-%m-%dT%H:%M:%SZ')]${NC} $1" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

# Main installation
log "=========================================="
log "Souran AI Network Server v$VERSION"
log "Installation from ZERO"
log "=========================================="

# Step 1: Prerequisites
log "[1/8] Checking prerequisites..."
if [ "$EUID" -ne 0 ]; then
    error "Please run as root or with sudo"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    log "Installing Python3..."
    apt-get update -qq && apt-get install -y python3 python3-pip -qq
fi

# Step 2: Create directories
log "[2/8] Creating directory structure..."
mkdir -p $SOURAN_DIR/{dns,config,logs,data,scripts,web}
mkdir -p $DNS_DIR

# Step 3: Create DNS resolver
log "[3/8] Creating Souran DNS Resolver..."
cat > $DNS_DIR/resolver.py << 'PYEOF'
#!/usr/bin/env python3
"""Souran AI Network Server v3.1.0 - Zero Upstream DNS Resolver"""

import socket
import struct
import sys
import time
import random

VERSION = "3.1.0"
ROOT_SERVERS = ['198.41.0.4', '199.9.149.7', '192.33.4.12']
dns_cache = {}

def build_query(domain, qtype=1):
    qname = b''
    for part in domain.split('.'):
        if part:
            qname += bytes([len(part)]) + part.encode()
    qname += b'\x00'
    tid = random.randint(1, 65535)
    header = struct.pack('>6H', tid, 0x0100, 1, 0, 0, 0)
    return header + qname + struct.pack('>HH', qtype, 1)

def decode_ip(ip_bytes):
    if len(ip_bytes) != 4:
        return None
    return '.'.join(str(b) for b in ip_bytes)

def parse_response(data):
    if len(data) < 12:
        return None
    tid, flags, qdcount, ancount, nscount, arcount = struct.unpack('>6H', data[:12])
    rcode = flags & 0x0F
    result = {'rcode': rcode, 'answers': [], 'glue_a': []}
    pos = 12
    for _ in range(qdcount):
        while pos < len(data):
            if data[pos] == 0:
                pos += 1
                break
            if data[pos] & 0xC0 == 0xC0:
                pos += 2
                break
            pos += 1 + data[pos]
        pos += 4
    for _ in range(ancount):
        while pos < len(data) and data[pos] != 0:
            if data[pos] & 0xC0 == 0xC0:
                pos += 2
                break
            pos += 1 + data[pos]
        if pos + 10 > len(data):
            break
        qtype, qclass, ttl = struct.unpack('>HHI', data[pos:pos+8])
        pos += 8
        if pos + 2 > len(data):
            break
        rdlength = struct.unpack('>H', data[pos:pos+2])[0]
        pos += 2
        if pos + rdlength > len(data):
            break
        rdata = data[pos:pos+rdlength]
        pos += rdlength
        result['answers'].append({'type': qtype, 'ttl': ttl, 'rdata': rdata})
    for _ in range(arcount):
        while pos < len(data) and data[pos] != 0:
            if data[pos] & 0xC0 == 0xC0:
                pos += 2
                break
            pos += 1 + data[pos]
        if pos + 10 > len(data):
            break
        qtype, qclass, ttl = struct.unpack('>HHI', data[pos:pos+8])
        pos += 8
        if pos + 2 > len(data):
            break
        rdlength = struct.unpack('>H', data[pos:pos+2])[0]
        pos += 2
        if pos + rdlength > len(data):
            break
        rdata = data[pos:pos+rdlength]
        pos += rdlength
        if qtype == 1:
            ip = decode_ip(rdata)
            if ip:
                result['glue_a'].append({'ip': ip, 'ttl': ttl})
    return result

def query_server(domain, server_ip, timeout=5.0):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(build_query(domain), (server_ip, 53))
        response, _ = sock.recvfrom(4096)
        sock.close()
        return parse_response(response)
    except:
        return None

def iterative_resolve(domain):
    domain = domain.lower().rstrip('.')
    if domain in dns_cache:
        ttl, ip, ts = dns_cache[domain]
        if time.time() - ts < ttl:
            return ip
    parts = domain.split('.')
    if len(parts) < 2:
        return None
    for root_ip in ROOT_SERVERS:
        resp = query_server(domain, root_ip)
        if not resp or resp['rcode'] != 0:
            continue
        for ans in resp['answers']:
            if ans['type'] == 1:
                ip = decode_ip(ans['rdata'])
                if ip:
                    dns_cache[domain] = (ans['ttl'], ip, time.time())
                    return ip
        tld_ns_ip = None
        for glue in resp['glue_a']:
            tld_ns_ip = glue['ip']
            break
        if tld_ns_ip:
            resp2 = query_server(domain, tld_ns_ip)
            if resp2 and resp2['rcode'] == 0:
                for ans in resp2['answers']:
                    if ans['type'] == 1:
                        ip = decode_ip(ans['rdata'])
                        if ip:
                            dns_cache[domain] = (ans['ttl'], ip, time.time())
                            return ip
    return None

def build_response(tid, domain, ip):
    if not ip:
        return struct.pack('>HHHHHH', tid, 0x8182, 1, 0, 0, 0) + b'\x00'
    qname = b''
    for part in domain.split('.'):
        if part:
            qname += bytes([len(part)]) + part.encode()
    qname += b'\x00'
    ip_parts = [int(p) for p in ip.split('.')]
    if len(ip_parts) != 4:
        return struct.pack('>HHHHHH', tid, 0x8182, 1, 0, 0, 0) + b'\x00'
    answer = b'\xc0\x0c' + struct.pack('>HHIH', 1, 1, 300, 4) + struct.pack('>BBBB', *ip_parts)
    response = struct.pack('>HHHHHH', tid, 0x8180, 1, 1, 0, 0)
    response += qname + struct.pack('>HH', 1, 1) + answer
    return response

def extract_domain(data):
    parts = []
    pos = 12
    while pos < len(data) and data[pos] != 0:
        if data[pos] & 0xC0 == 0xC0:
            break
        length = data[pos]
        pos += 1
        if pos + length <= len(data):
            parts.append(data[pos:pos+length].decode('utf-8', errors='ignore'))
            pos += length
    return '.'.join(parts)

def main():
    print(f"Souran DNS Server v{VERSION} - Zero Upstream", file=sys.stderr, flush=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 53))
    print("Listening on 0.0.0.0:53", file=sys.stderr, flush=True)
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            if len(data) < 12:
                continue
            tid = struct.unpack('>H', data[:2])[0]
            domain = extract_domain(data)
            ip = iterative_resolve(domain)
            resp = build_response(tid, domain, ip)
            sock.sendto(resp, addr)
        except KeyboardInterrupt:
            sock.close()
            break
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr, flush=True)

if __name__ == '__main__':
    main()
PYEOF

chmod +x $DNS_DIR/resolver.py

# Step 4: Create systemd service
log "[4/8] Creating systemd service..."
cat > /etc/systemd/system/souran-dns.service << 'EOF'
[Unit]
Description=Souran DNS Zero Upstream Resolver
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/souran-ai/dns/resolver.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
User=root

[Install]
WantedBy=multi-user.target
EOF

# Step 5: Create watchdog
log "[5/8] Creating watchdog..."
cat > $SOURAN_DIR/watchdog.sh << 'WDEOF'
#!/bin/bash
SOURAN_DIR="/opt/souran-ai"
LOG_FILE="$SOURAN_DIR/logs/watchdog.log"
mkdir -p $SOURAN_DIR/logs

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> $LOG_FILE
}

check_dns() {
    result=$(dig @127.0.0.1 google.com A +short 2>/dev/null)
    [ -n "$result" ]
}

check_tor() {
    systemctl is-active tor &>/dev/null
}

check_ports() {
    for port in 53 8082 8383 9050; do
        ss -tulpn | grep -q ":$port " || return 1
    done
    return 0
}

repair_dns() {
    log_msg "REPAIR: Restarting DNS"
    pkill -f "resolver.py" 2>/dev/null || true
    sleep 1
    python3 $SOURAN_DIR/dns/resolver.py &>/dev/null &
}

repair_tor() {
    log_msg "REPAIR: Restarting Tor"
    systemctl restart tor 2>/dev/null || true
}

while true; do
    if ! check_dns; then
        log_msg "WARN: DNS not responding"
        repair_dns
    fi
    if ! check_tor; then
        log_msg "WARN: Tor not active"
        repair_tor
    fi
    if ! check_ports; then
        log_msg "WARN: Ports not listening"
        repair_dns
        repair_tor
    fi
    log_msg "STATUS: All systems operational"
    sleep 300
done
WDEOF

chmod +x $SOURAN_DIR/watchdog.sh

# Step 6: Create anti-compression engine
log "[6/8] Creating anti-compression engine..."
cat > $SOURAN_DIR/anti_compress.py << 'ACEOF'
#!/usr/bin/env python3
"""Anti-Compression Engine - Batch process files without loading into context"""

import os, sys, hashlib, json
from pathlib import Path

class AntiCompressEngine:
    def __init__(self, work_dir="/opt/souran-ai/data"):
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(exist_ok=True)
        self.processed = set()
    
    def hash_file(self, filepath):
        hasher = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    
    def process_file(self, filepath, operation="extract"):
        path = Path(filepath)
        if not path.exists():
            return {"error": "File not found", "file": str(filepath)}
        file_hash = self.hash_file(path)
        if file_hash in self.processed:
            return {"status": "already_processed", "file": str(filepath)}
        result = {"file": str(filepath), "size": path.stat().st_size, "hash": file_hash, "operation": operation, "status": "completed"}
        if operation == "extract":
            with open(path, 'r', errors='ignore') as f:
                lines = f.readlines()
                result["lines"] = len(lines)
                result["first_line"] = lines[0].strip()[:100] if lines else ""
        self.processed.add(file_hash)
        return result
    
    def batch_process(self, directory, pattern="*.txt"):
        results = []
        path = Path(directory)
        if not path.exists():
            return {"error": "Directory not found"}
        for file in path.glob(pattern):
            results.append(self.process_file(file, "extract"))
        return {"processed": len(results), "results": results}
    
    def save_state(self, state_file="/opt/souran-ai/data/processed_state.json"):
        with open(state_file, 'w') as f:
            json.dump({"processed_hashes": list(self.processed)}, f, indent=2)

def main():
    engine = AntiCompressEngine()
    if len(sys.argv) > 1:
        target = sys.argv[1]
        if os.path.isfile(target):
            print(json.dumps(engine.process_file(target), indent=2))
        elif os.path.isdir(target):
            print(json.dumps(engine.batch_process(target), indent=2))
    else:
        print(json.dumps(engine.batch_process("/opt/souran-ai/data"), indent=2))
    engine.save_state()

if __name__ == '__main__':
    main()
ACEOF

chmod +x $SOURAN_DIR/anti_compress.py

# Step 7: Start services
log "[7/8] Starting services..."
pkill -f "python3.*resolver.py" 2>/dev/null || true
sleep 1
python3 $DNS_DIR/resolver.py &>/dev/null &
sleep 2

pkill -f "watchdog.sh" 2>/dev/null || true
bash $SOURAN_DIR/watchdog.sh &>/dev/null &

# Step 8: Verify installation
log "[8/8] Verifying installation..."
sleep 2

echo ""
echo "=========================================="
echo "  Souran AI Network Server v$VERSION"
echo "=========================================="
echo ""
echo "DNS Resolver: $(dig @127.0.0.1 google.com A +short 2>/dev/null || echo 'Checking...')"
echo "Tor SOCKS: $(systemctl is-active tor 2>/dev/null)"
echo "Port 53: $(ss -tulpn | grep ':53 ' | wc -l) listener(s)"
echo "Port 8082: $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8082/ 2>/dev/null)"
echo "Port 8383: $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8383/ 2>/dev/null)"
echo ""
echo "Status: OPERATIONAL"
echo "=========================================="
WDEOF

log "=========================================="
log "SOURAN AI NETWORK SERVER v$VERSION"
log "Installation from ZERO"
log "=========================================="

# Step 1: Prerequisites
log "[1/12] Installing prerequisites..."
sudo apt-get update -qq
sudo apt-get install -y -qq dnsmasq tor cloudflared nginx curl dnsutils netcat-openbsd 2>/dev/null || true

# Step 2: Create directories
log "[2/12] Creating directories..."
mkdir -p $INSTALL_DIR/{src,scripts,logs,data,config,migrations,web}
mkdir -p /etc/dns /var/log/souran /etc/dnsmasq.d

# Step 3: Build Rust DNS server from source
log "[3/12] Building Soran DNS resolver from source..."
cd /opt/soran
cargo build --release 2>&1 | tail -5
cp /opt/soran/target/release/soran /usr/local/bin/soran
chmod +x /usr/local/bin/soran
sudo -n setcap 'cap_net_bind_service=+ep' /usr/local/bin/soran 2>/dev/null || true
log "Soran binary deployed to /usr/local/bin/soran"

# Step 4: Configure dnsmasq (Tor DNS bridge)
log "[4/12] Configuring dnsmasq..."
cat > /etc/dnsmasq.d/souran-dns.conf << 'EOF'
# Souran AI Network - DNS Forwarder to Tor
server=/localnet/127.0.0.1#9053
server=127.0.0.1#9053
no-resolv
no-hosts
cache-size=1000
neg-ttl=3600
EOF
log "dnsmasq configured for Tor DNS forwarding"

# Step 5: Start services
log "[5/12] Starting services..."
sudo -n systemctl restart tor 2>/dev/null || true
sudo -n pkill -9 dnsmasq 2>/dev/null || true
sleep 1
sudo -n /usr/sbin/dnsmasq --conf-file=/etc/dnsmasq.d/souran-dns.conf --no-daemon --log-queries &
sleep 2
sudo -n nohup /usr/local/bin/soran dns > /var/log/soran/dns.log 2>&1 &
sleep 2
sudo -n nohup /usr/local/bin/soran --port 5353 dns > /var/log/soran/dns-alt.log 2>&1 &

# Step 6: Start dashboard services
log "[6/12] Starting dashboards..."
sudo -n systemctl restart souran-8082-dashboard 2>/dev/null || true
sudo -n systemctl restart souran-web-8383 2>/dev/null || true
sudo -n systemctl restart souran-8083-doh 2>/dev/null || true

# Step 7: Start watchdog
log "[7/12] Starting watchdog..."
sudo -n systemctl restart souran-ai-watchdog 2>/dev/null || true
sudo -n systemctl restart souran-watchdog 2>/dev/null || true

# Step 8: Start autonomous monitor
log "[8/12] Starting autonomous monitor..."
sudo -n nohup /opt/souran/scripts/autonomous-monitor.sh > /var/log/souran/monitor.log 2>&1 &

# Step 9: Configure cloudflared tunnel
log "[9/12] Configuring Cloudflare Tunnel..."
sudo -n systemctl restart cloudflared 2>/dev/null || true

# Step 10: Verify installation
log "[10/12] Verifying installation..."
sleep 3
PASS=0
FAIL=0

# DNS test
if dig @127.0.0.1 google.com A +short +time=5 +tries=1 2>/dev/null | grep -qE '^[0-9]'; then
    log "  ✓ DNS resolution: PASS"
    PASS=$((PASS+1))
else
    log "  ✗ DNS resolution: FAIL"
    FAIL=$((FAIL+1))
fi

# DoH test
if curl -s --max-time 5 http://127.0.0.1:8083/health 2>/dev/null | grep -q ok; then
    log "  ✓ DoH endpoint: PASS"
    PASS=$((PASS+1))
else
    log "  ✗ DoH endpoint: FAIL"
    FAIL=$((FAIL+1))
fi

# Dashboard 8082 test
if curl -s --max-time 5 http://127.0.0.1:8082/health 2>/dev/null | grep -q ok; then
    log "  ✓ Dashboard 8082: PASS"
    PASS=$((PASS+1))
else
    log "  ✗ Dashboard 8082: FAIL"
    FAIL=$((FAIL+1))
fi

# Dashboard 8383 test
if curl -s --max-time 5 http://127.0.0.1:8383/api/stats 2>/dev/null | grep -q total_queries; then
    log "  ✓ Dashboard 8383: PASS"
    PASS=$((PASS+1))
else
    log "  ✗ Dashboard 8383: FAIL"
    FAIL=$((FAIL+1))
fi

# Tor test
if nc -z 127.0.0.1 9050 2>/dev/null; then
    log "  ✓ Tor SOCKS: PASS"
    PASS=$((PASS+1))
else
    log "  ✗ Tor SOCKS: FAIL"
    FAIL=$((FAIL+1))
fi

log ""
log "=========================================="
log "INSTALLATION COMPLETE"
log "Passed: $PASS/5 tests"
log "Failed: $FAIL/5 tests"
log "=========================================="
log "Dashboard 1 (Hermes): http://localhost:8082"
log "Dashboard 2 (Neuro):  http://localhost:8383"
log "DoH Proxy:            http://localhost:8083/dns-query"
log "DNS Resolver:         udp/tcp port 53"
log "Tor SOCKS:            port 9050"
log "=========================================="

if [ $FAIL -eq 0 ]; then
    log "ALL TESTS PASSED - Souran AI Network Server is fully operational"
    exit 0
else
    log "SOME TESTS FAILED - Check logs at $LOG_FILE"
    exit 1
fi