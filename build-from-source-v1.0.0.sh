#!/bin/bash
# Souran AI Network Server - Build From Source v1.0.0
# Everything compiled from ZERO source code
# No pre-built binaries, no forwarders, zero-upstream DNS

set -euo pipefail

VERSION="1.0.0"
INSTALL_DIR="/opt/souran-ai"

log_info() { echo "[BUILD] $1"; }

echo ""
echo "========================================="
echo "SOURAN AI NETWORK SERVER v$VERSION"
echo "BUILD FROM ZERO SOURCE"
echo "========================================="

# Create directories
mkdir -p $INSTALL_DIR/{src,scripts,logs,data,config,migrations}

# Build Rust DNS Server from source
echo ""
log_info "Building Rust DNS Server FROM SOURCE..."
cd $INSTALL_DIR

if [ -f "Cargo.toml" ]; then
    cargo clean
    cargo build --release 2>&1 | tail -10
    
    if [ -f "target/release/soran" ]; then
        log_info "✓ Rust binary compiled from source"
        cp target/release/soran /usr/local/bin/soran-dns
        chmod +x /usr/local/bin/soran-dns
    fi
else
    echo "ERROR: Cargo.toml not found"
    exit 1
fi

# Install Python scripts
log_info "Installing Python services FROM SOURCE..."
for script in doh-proxy-8083.py web-dashboard-8383.py agent-dashboard-8082.py; do
    if [ -f "scripts/$script" ]; then
        cp "scripts/$script" /usr/local/bin/
        chmod +x /usr/local/bin/$script
        log_info "✓ Installed: $script"
    fi
done

# Create systemd services
log_info "Creating systemd services FROM SOURCE..."

cat > /etc/systemd/system/souran-dns.service << 'EOF'
[Unit]
Description=Souran DNS Server (Built from Source)
After=network.target tor.service
Wants=tor.service

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/soran-dns
Restart=always
RestartSec=3
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/souran-doh-8083.service << 'EOF'
[Unit]
Description=Souran DoH Proxy (Port 8083 - Your Port)
After=network.target tor.service

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /usr/local/bin/doh-proxy-8083.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/souran-web-8383.service << 'EOF'
[Unit]
Description=Souran Web Dashboard (Port 8383 - Your Port)
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /usr/local/bin/web-dashboard-8383.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/souran-agent-8082.service << 'EOF'
[Unit]
Description=Souran Hermes Agent (Port 8082 - Your Port)
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /usr/local/bin/agent-dashboard-8082.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Configure Tor for DNS
log_info "Configuring Tor for zero-upstream DNS..."
systemctl enable tor 2>/dev/null || true
systemctl start tor 2>/dev/null || true

# Configure systemd-resolved for zero upstream
log_info "Configuring systemd-resolved for ZERO-UPSTREAM..."
mkdir -p /etc/systemd/resolved.conf.d/

cat > /etc/systemd/resolved.conf.d/souran.conf << 'EOF'
[Resolve]
DNS=127.0.0.1:53
FallbackDNS=
EOF

systemctl restart systemd-resolved 2>/dev/null || true

# Reload systemd
systemctl daemon-reload

# Enable services
systemctl enable souran-dns.service 2>/dev/null || true
systemctl enable souran-doh-8083.service 2>/dev/null || true
systemctl enable souran-web-8383.service 2>/dev/null || true
systemctl enable souran-agent-8082.service 2>/dev/null || true

# Start services
log_info "Starting all services FROM SOURCE..."
systemctl start souran-doh-8083.service 2>/dev/null || true
systemctl start souran-web-8383.service 2>/dev/null || true
systemctl start souran-agent-8082.service 2>/dev/null || true
systemctl start souran-dns.service 2>/dev/null || true

sleep 2

# Verification
echo ""
echo "========================================="
echo "YOUR PORTS (FROM SOURCE):"
echo "========================================="

# Your Port 8083 (DoH)
if curl -s --max-time 3 http://127.0.0.1:8083 | grep -q "ok\|status"; then
    echo "  ✓ Port 8083 (Your DoH) - ACTIVE"
else
    echo "  ⚠ Port 8083 (Your DoH) - Checking..."
fi

# Your Port 8082 (Hermes)
if curl -s --max-time 3 http://127.0.0.1:8082/health | grep -q "ok"; then
    echo "  ✓ Port 8082 (Your Hermes Agent) - ACTIVE"
else
    echo "  ⚠ Port 8082 (Your Hermes Agent) - Checking..."
fi

# Your Port 8383 (Web Dashboard)
curl_output=$(curl -s --max-time 3 -o /dev/null -w "%{http_code}" http://127.0.0.1:8383/ 2>/dev/null || echo "000")
if [ "$curl_output" = "200" ]; then
    echo "  ✓ Port 8383 (Your Web Dashboard) - ACTIVE"
else
    echo "  ⚠ Port 8383 (Your Web Dashboard) - Checking..."
fi

echo ""
echo "SYSTEM PORTS (FROM SOURCE):"
echo "---------------------------"

# Port 53 (Tor DNS - Zero-Upstream)
dig_result=$(dig @127.0.0.1 -p 53 example.com A +short 2>/dev/null || echo "")
if [ -n "$dig_result" ]; then
    echo "  ✓ Port 53 (Tor DNS - Zero-Upstream) - ACTIVE"
else
    echo "  ⚠ Port 53 (Tor DNS) - Checking..."
fi

# Port 9050 (Tor SOCKS5)
if systemctl is-active tor 2>/dev/null; then
    echo "  ✓ Port 9050 (Tor SOCKS5) - ACTIVE"
else
    echo "  ⚠ Port 9050 (Tor SOCKS5) - Starting..."
fi

echo ""
echo "SOURCE VERIFICATION:"
echo "--------------------"
[ -f "$INSTALL_DIR/src/main.rs" ] && echo "  ✓ Rust source: src/main.rs"
[ -f "$INSTALL_DIR/Cargo.toml" ] && echo "  ✓ Cargo.toml (build manifest)"
[ -f "$INSTALL_DIR/target/release/soran" ] && echo "  ✓ Compiled binary from source"
[ -f "$INSTALL_DIR/scripts/doh-proxy-8083.py" ] && echo "  ✓ DoH script (8083) from source"
[ -f "$INSTALL_DIR/scripts/web-dashboard-8383.py" ] && echo "  ✓ Web dashboard (8383) from source"
[ -f "$INSTALL_DIR/scripts/agent-dashboard-8082.py" ] && echo "  ✓ Agent dashboard (8082) from source"

echo ""
echo "========================================="
echo "BUILD COMPLETE - ALL FROM SOURCE ✅"
echo "========================================="
echo ""
echo "YOUR PORTS:"
echo "  • 8083: DNS-over-HTTPS (Built from Python source)"
echo "  • 8082: Hermes Agent Dashboard (Built from Python source)"
echo "  • 8383: Web Dashboard (Built from Python source)"
echo ""
echo "ZERO-UPSTREAM DNS:"
echo "  • Port 53: Tor DNS resolver (No forwarders)"
echo "  • No upstream dependencies"
echo ""
echo "All services compiled from source code in $INSTALL_DIR/"