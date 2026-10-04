#!/bin/bash
# Souran AI Network Server Installation Script v5.2.0
# Builds from source on Ubuntu
set -euo pipefail

echo "===(Souran AI Network Server v5.2.0)================================="
echo ""
echo "[1/12] Checking system requirements..."
if [ -f /etc/debian_version ]; then
    echo "  ✓ Debian/Ubuntu detected"
else
    echo "  ✗ Unsupported OS. Only Ubuntu/Debian is supported."
    exit 1
fi

echo "[2/12] Checking Souran AI base directory..."
if [ -d "/opt/souran-ai" ]; then
    echo "  ✓ /opt/souran-ai exists"
else
    echo "  ✗ Directory not found. Run build-from-source.sh first."
    exit 1
fi

echo "[3/12] Installing Python dependencies..."
source /opt/souran-ai/venv/bin/activate 2>/dev/null || python3 -m venv /opt/souran-ai/venv
pip install -q fastapi uvicorn python-multipart httpx 2>/dev/null
echo "  ✓ Python dependencies installed"

echo "[4/12] Registering systemd services..."
if [ -f /etc/systemd/system/souran-web-8383.service ]; then
    echo "  ✓ Web dashboard service (8383)"
else
    echo "  ! Creating web dashboard service..."
    cat > /etc/systemd/system/souran-web-8383.service << 'EOFSERVICE'
[Unit]
Description=Souran AI Web Dashboard (Port 8383)
After=network.target dns.service
Wants=network.target

[Service]
Type=simple
User=reza
WorkingDirectory=/opt/souran-ai
ExecStart=/usr/bin/python3 /opt/souran-ai/web-dashboard-8383.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOFSERVICE
fi

if [ -f /etc/systemd/system/souran-8082-dashboard.service ]; then
    echo "  ✓ Hermes Agent service (8082)"
fi

if [ -f /etc/systemd/system/souran-doh-8083.service ]; then
    echo "  ✓ DoH Proxy service (8083)"
fi

echo "[5/12] Reloading systemd daemon..."
sudo systemctl daemon-reload 2>/dev/null || true

echo "[6/12] Starting DNS resolver..."
sudo systemctl restart souran-dns 2>/dev/null || echo "  ! DNS service may need manual start"

echo "[7/12] Starting Tor bypass..."
sudo systemctl restart tor 2>/dev/null || echo "  ! Tor may need manual start"

echo "[8/12] Starting Web Dashboard on port 8383..."
sudo systemctl restart souran-web-8383 2>/dev/null || echo "  ! Web dashboard may need manual start"

echo "[9/12] Starting Hermes Agent Dashboard on port 8082..."
sudo systemctl restart souran-8082-dashboard 2>/dev/null || echo "  ! Agent dashboard may need manual start"

echo "[10/12] Starting DoH Proxy on port 8083..."
sudo systemctl restart souran-doh-8083 2>/dev/null || echo "  ! DoH service may need manual start"

echo "[11/12] Verifying service status..."
sleep 2

check_port() {
    local port=$1
    local name=$2
    if ss -tlnp 2>/dev/null | grep -q ":$port "; then
        echo "  ✓ $name on port $port"
    else
        echo "  ! $name not listening on port $port"
    fi
}

check_port 53 "DNS Resolver"
check_port 8080 "Technitium Admin"
check_port 8082 "Hermes Agent"
check_port 8083 "DoH Proxy"
check_port 8383 "Web Dashboard"
check_port 9050 "Tor Proxy"

echo "[12/12] Testing DNS resolution..."
if timeout 5 nslookup google.com 127.0.0.1 >/dev/null 2>&1; then
    echo "  ✓ DNS resolution working"
else
    echo "  ! DNS resolution test inconclusive"
fi

echo ""
echo "===================================================================="
echo "  Souran AI Network Server v5.2.0 - Installation Complete"
echo "===================================================================="
echo ""
echo "  Available Dashboards:"
echo "    http://localhost:8383/  (Web Dashboard - Neuro Analytics)"
echo "    http://localhost:8082/  (Hermes Agent Control)"
echo "    http://localhost:8080/  (Technitium DNS Admin)"
echo ""
echo "  User DNS Service:"
echo "    http://localhost:8083/  (DoH / DNS-over-HTTPS)"
echo ""
echo "  CLI Tool:"
echo "    /opt/souran-ai/souran-ai check"
echo "    /opt/souran-ai/souran-ai status"
echo "    /opt/souran-ai/souran-ai restart"
echo ""
echo "  Domains: sitet.top, cafenetmordad.ir, mordaddns.ir"
echo "===================================================================="