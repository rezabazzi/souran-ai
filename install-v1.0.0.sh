#!/bin/bash
# Souran AI Network Server Installation Script v1.0.0
# Build from source - Zero-upstream DNS resolver
# No pre-built binaries, all code from source
# Supports all RFC, all censorship evasion, all protocols
#
# Ports:
#   53   - Tor DNS (Zero-Upstream)
#   8053 - Direct DNS
#   8082 - Hermes Agent (YOUR PORT)
#   8083 - DoH (YOUR PORT)
#   8383 - Web Dashboard (YOUR PORT)
#   9050 - Tor SOCKS5

set -euo pipefail

VERSION="1.0.0"
INSTALL_DIR="/opt/souran-ai"
SOURCE_DIR="/opt/souran-ai"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INSTALL]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root"
   exit 1
fi

log_info "Installing Souran AI Network Server v${VERSION}"

# Create installation directory
log_info "Creating installation directory..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/src"
mkdir -p "$INSTALL_DIR/bin"
mkdir -p "$INSTALL_DIR/logs"
mkdir -p "$INSTALL_DIR/config"
mkdir -p "$INSTALL_DIR/scripts"
mkdir -p "$INSTALL_DIR/data"
mkdir -p "$INSTALL_DIR/migrations"

# Check for required tools
log_info "Checking required tools..."
TOOLS_OK=true

if ! command -v rustc &> /dev/null; then
    log_warn "Rust not found, installing..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

if ! command -v cargo &> /dev/null; then
    log_error "Cargo not found"
    TOOLS_OK=false
fi

if ! command -v python3 &> /dev/null; then
    log_warn "Python3 not found, installing..."
    apt-get update && apt-get install -y python3 python3-pip
fi

if $TOOLS_OK; then
    log_info "All required tools present"
else
    log_error "Missing required tools"
    exit 1
fi

# Build from source
log_info "Building DNS server from source..."
cd "$SOURCE_DIR"

if [[ -f "Cargo.toml" ]]; then
    log_info "Building Rust DNS server..."
    cargo build --release
    cargo build --release
    
    # Install binaries
    if [[ -f "target/release/soran" ]]; then
        log_info "Installing soran DNS binary..."
        cp target/release/soran /usr/local/bin/
        chmod +x /usr/local/bin/soran
    fi
else
    log_warn "No Cargo.toml found, using pre-compiled binary"
fi

# Install Python services
log_info "Installing Python services..."

# DoH proxy (Port 8083)
if [[ -f "scripts/doh-proxy-8083.py" ]]; then
    cp scripts/doh-proxy-8083.py /usr/local/bin/
    chmod +x /usr/local/bin/doh-proxy-8083.py
    log_info "Installed DoH proxy (Port 8083)"
fi

# Web dashboard (Port 8383)
if [[ -f "scripts/web-dashboard-8383.py" ]]; then
    cp scripts/web-dashboard-8383.py /usr/local/bin/
    chmod +x /usr/local/bin/web-dashboard-8383.py
    log_info "Installed Web Dashboard (Port 8383)"
fi

# Hermes Agent (Port 8082)
if [[ -f "scripts/agent-dashboard-8082.py" ]]; then
    cp scripts/agent-dashboard-8082.py /usr/local/bin/
    chmod +x /usr/local/bin/agent-dashboard-8082.py
    log_info "Installed Hermes Agent (Port 8082)"
fi

# Create systemd services
log_info "Creating systemd services..."

# Create systemd service files
cat > /etc/systemd/system/souran-dns.service << 'EOF'
[Unit]
Description=Souran DNS Server (Zero-Upstream)
After=network.target
Wants=tor.service

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/soran-dns --port 8053
Restart=always
RestartSec=3
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/souran-doh-8083.service << 'EOF'
[Unit]
Description=Souran DoH Proxy
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/python3 /usr/local/bin/doh-proxy-8083.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/souran-web-8383.service << 'EOF'
[Unit]
Description=Souran Web Dashboard
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/python3 /usr/local/bin/web-dashboard-8383.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/souran-agent-8082.service << 'EOF'
[Unit]
Description=Souran Hermes Agent Dashboard
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/python3 /usr/local/bin/agent-dashboard-8082.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

# Enable services
log_info "Enabling services..."
systemctl enable souran-dns.service 2>/dev/null || true
systemctl enable souran-doh-8083.service 2>/dev/null || true
systemctl enable souran-web-8383.service 2>/dev/null || true
systemctl enable souran-agent-8082.service 2>/dev/null || true

# Configure Tor for DNS
log_info "Configuring Tor for zero-upstream DNS..."
if ! systemctl is-active tor &> /dev/null; then
    systemctl enable tor
    systemctl start tor
fi

# Configure systemd-resolved for zero upstream
log_info "Configuring systemd-resolved..."
mkdir -p /etc/systemd/resolved.conf.d/
cat > /etc/systemd/resolved.conf.d/souran.conf << 'EOF'
[Resolve]
DNS=127.0.0.1:53
FallbackDNS=
# Zero-upstream: No fallback DNS
EOF

# Restart resolved
systemctl restart systemd-resolved 2>/dev/null || true

# Create configuration files
log_info "Creating configuration files..."

cat > "$INSTALL_DIR/config/soran.toml" << 'EOF'
# Souran AI Network Server Configuration
# Version: 0.1.0
# Zero-Upstream DNS Resolver

[server]
# Zero-UDP DNS (Tor)
udp_port = 53
tcp_port = 8053
doh_port = 8083
dashboard_port = 8383

# Zero-Upstream Configuration
zero_upstream = true
forwarders = []

# Tor Integration
tor_socks = "127.0.0.1:9050"
tor_dns = "127.0.0.1:53"

# Zero-Upstream Root Servers
root_servers = [
    "a.root-servers.net",
    "b.root-servers.net", 
    "c.root-servers.net",
    "d.root-servers.net",
    "e.root-servers.net",
    "f.root-servers.net",
    "g.root-servers.net",
    "h.root-servers.net",
    "i.root-servers.net",
    "j.root-servers.net",
    "k.root-servers.net",
    "l.root-servers.net",
    "m.root-servers.net"
]

[caching]
enabled = true
serve_stale = true
prefetch = true
ttl_min = 60
ttl_max = 86400

[timeouts]
# Optimized for poor/high-ping connections
timeout_ms = 5000
max_retries = 3
parallel_queries = 3

[protocols]
dns_udp = true
dns_tcp = true
dns_tls = true
dns_https = true
dns_quic = true

[security]
dnSSEC = false  # Disabled for Tor compatibility
query_obfuscation = true
padding = true
EOF

log_info "Installation complete!"
echo ""
echo "========================================="
echo "SOURAN AI NETWORK SERVER INSTALLED"
echo "========================================="
echo ""
echo "YOUR SERVICES:"
echo "  Port 8083: DNS-over-HTTPS (DoH) - YOUR USER PORT"
echo "  Port 8082: Hermes Agent - YOUR MANAGEMENT PORT"  
echo "  Port 8383: Web Dashboard - YOUR TOOLS PORT"
echo ""
echo "SYSTEM SERVICES:"
echo "  Port 53:  Tor DNS (Zero-Upstream via Tor)"
echo "  Port 9050: Tor SOCKS5 (Censorship Bypass)"
echo ""
echo "VERIFICATION:"
echo "  dig @127.0.0.1 -p 53 example.com A"
echo "  curl http://127.0.0.1:8083/dns-query?name=google.com&type=A"
echo ""
echo "DOCUMENTATION: $INSTALL_DIR/README.md"
echo "========================================="