#!/bin/bash
# Souran AI Network Server Installation Script v0.1.0
# Built from source - Zero upstream DNS resolver
# Author: Reza Bazzi (رضا بزی)
# Date: 2026-09-30

set -e

echo "=========================================="
echo "Souran AI Network Server v0.1.0"
echo "Installation Script"
echo "=========================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
   echo "Please run as root"
   exit 1
fi

# Create version file
cat > /opt/souran-ai/VERSION << EOF
version = "0.1.0"
build_date = "$(date +%Y-%m-%d)"
rust_version = "1.75.0"
soran_version = "5.1.0"
EOF

echo "✓ Version file created"

# Stop existing services
echo "Stopping existing services..."
systemctl stop souran-dns 2>/dev/null || true
systemctl stop souran-doh-8083 2>/dev/null || true
systemctl stop souran-web-8383 2>/dev/null || true
echo "✓ Services stopped"

# Reload systemd
systemctl daemon-reload

# Start services
echo "Starting services..."
systemctl start souran-dns
systemctl start souran-doh-8083
systemctl start souran-web-8383
systemctl enable souran-dns
systemctl enable souran-doh-8083
systemctl enable souran-web-8383
echo "✓ Services started"

# Wait for services to fully start
sleep 3

# Verify services
echo ""
echo "Verifying services..."
echo "====================="

DNS_STATUS=$(systemctl is-active souran-dns)
DOH_STATUS=$(systemctl is-active souran-doh-8083)
WEB_STATUS=$(systemctl is-active souran-web-8383)

echo "DNS Service (souran-dns): $DNS_STATUS"
echo "DoH Service (8083): $DOH_STATUS"
echo "Web Dashboard (8383): $WEB_STATUS"

# Test DoH endpoint
echo ""
echo "Testing DoH endpoint on port 8083..."
DOH_TEST=$(curl -s "http://127.0.0.1:8083/dns-query?name=example.com&type=A" \
  -H "Accept: application/dns-json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('Answer',[{}])[0].get('data','ERROR') if d.get('Answer') else 'ERROR')")

if [ "$DOH_TEST" != "ERROR" ]; then
    echo "✓ DoH working: example.com -> $DOH_TEST"
else
    echo "✗ DoH test failed"
fi

# Check ports
echo ""
echo "Port Status:"
echo "============"
ss -tlnp | grep -E ':(8053|8082|8083|8383|9050)\s' | while read line; do
    echo "✓ $line"
done

echo ""
echo "=========================================="
echo "Installation Complete!"
echo "=========================================="
echo ""
echo "Access Points:"
echo "  DoH endpoint (User Port):  http://127.0.0.1:8083/dns-query"
echo "  Hermes Dashboard (Port 8082): http://127.0.0.1:8082/"
echo "  Web Dashboard (Neuro):  http://127.0.0.1:8383/"
echo "  Tor Proxy:        SOCKS5 on port 9050"
echo ""
echo "Configuration:"
echo "  soran.toml: /opt/souran-ai/soran.toml"
echo "  Build source: /opt/soran/"
echo "  Version: 0.1.0"
echo ""
