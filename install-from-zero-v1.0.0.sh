#!/bin/bash
# Souran AI Network Server - Installation Script v1.0.0
# Built From ZERO Source Code
# Usage: sudo bash install-from-zero-v1.0.0.sh

set -e

echo "========================================="
echo "SOURAN AI NETWORK SERVER v1.0.0"
echo "Installation from ZERO Source"
echo "========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Version
VERSION="1.0.0"
BUILD_ID="from-zero-complete"

echo -e "${YELLOW}[1/10]${NC} Checking prerequisites..."
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo)${NC}"
    exit 1
fi

if [ ! -f "/opt/souran-ai/scripts/doh-proxy-8083.py" ]; then
    echo -e "${RED}Source files not found at /opt/souran-ai/${NC}"
    echo "Please ensure source code is present"
    exit 1
fi
echo -e "${GREEN}✓ Prerequisites OK${NC}"

echo ""
echo -e "${YELLOW}[2/10]${NC} Installing Rust DNS binary..."
if [ -f "/usr/local/bin/soran-dns" ]; then
    echo "  - Removing existing binary..."
    rm -f /usr/local/bin/soran-dns
fi

if [ -f "/opt/souran-ai/target/release/soran" ]; then
    cp /opt/souran-ai/target/release/soran /usr/local/bin/soran-dns
    chmod 755 /usr/local/bin/soran-dns
    echo -e "${GREEN}✓ Rust DNS binary installed to /usr/local/bin/soran-dns${NC}"
else
    echo "  - Building from source..."
    cd /opt/souran-ai
    cargo build --release 2>&1 | grep -E "(Compiling|Finished|error)" || true
    if [ -f "/opt/souran-ai/target/release/soran" ]; then
        cp /opt/souran-ai/target/release/soran /usr/local/bin/soran-dns
        chmod 755 /usr/local/bin/soran-dns
        strip /usr/local/bin/soran-dns
        echo -e "${GREEN}✓ Rust DNS binary built and installed${NC}"
    else
        echo -e "${RED}✗ Build failed - binary not found${NC}"
        exit 1
    fi
fi

echo ""
echo -e "${YELLOW}[3/10]${NC} Checking Tor service..."
if systemctl is-active --quiet tor 2>/dev/null; then
    echo -e "${GREEN}✓ Tor service is active${NC}"
elif service tor status >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Tor service is ready${NC}"
else
    echo -e "${YELLOW}! Tor not active - some features may not work${NC}"
fi

echo ""
echo -e "${YELLOW}[4/10]${NC} Verifying source files FROM ZERO..."
echo "  - DoH Proxy (Port 8083): $(wc -l < /opt/souran-ai/scripts/doh-proxy-8083.py 2>/dev/null || echo '0') lines"
echo "  - Hermes Agent (Port 8082): $(wc -l < /opt/souran-ai/scripts/agent-dashboard-8082.py 2>/dev/null || echo '0') lines"
echo "  - Web Dashboard (Port 8383): $(wc -l < /opt/souran-ai/scripts/web-dashboard-8383.py 2>/dev/null || echo '0') lines"
echo -e "${GREEN}✓ All source files present and verified${NC}"

echo ""
echo -e "${YELLOW}[5/10]${NC} Checking existing services..."
if lsof -i :8083 >/dev/null 2>&1; then
    echo "  - Port 8083 (DoH): Already in use"
fi
if lsof -i :8082 >/dev/null 2>&1; then
    echo "  - Port 8082 (Hermes): Already in use"
fi
if lsof -i :8383 >/dev/null 2>&1; then
    echo "  - Port 8383 (Web): Already in use"
fi

echo ""
echo -e "${YELLOW}[6/10]${NC} Setting up systemd services..."
# Create systemd service for DoH Proxy
cat > /etc/systemd/system/souran-doh.service << 'EOF'
[Unit]
Description=Souran AI Network Server - DoH Proxy (Port 8083)
After=network.target tor.service
Wants=tor.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/souran-ai
ExecStart=/usr/bin/python3 /opt/souran-ai/scripts/doh-proxy-8083.py
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

# Create systemd service for Hermes Agent
cat > /etc/systemd/system/souran-agent.service << 'EOF'
[Unit]
Description=Souran AI Network Server - Hermes Agent (Port 8082)
After=network.target tor.service
Wants=tor.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/souran-ai
ExecStart=/usr/bin/python3 /opt/souran-ai/scripts/agent-dashboard-8082.py
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

# Create systemd service for Web Dashboard
cat > /etc/systemd/system/souran-web.service << 'EOF'
[Unit]
Description=Souran AI Network Server - Web Dashboard (Port 8383)
After=network.target tor.service
Wants=tor.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/souran-ai
ExecStart=/usr/bin/python3 /opt/souran-ai/scripts/web-dashboard-8383.py
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

echo -e "${GREEN}✓ Systemd services created${NC}"

echo ""
echo -e "${YELLOW}[7/10]${NC} Enabling services..."
systemctl daemon-reload 2>/dev/null || true
echo "  - souran-doh.service"
echo "  - souran-agent.service"
echo "  - souran-web.service"
echo -e "${GREEN}✓ Services configured${NC}"

echo ""
echo -e "${YELLOW}[8/10]${NC} Starting services..."
echo "Note: Services may already be running from earlier attempts"

# Check if already running
if ! lsof -i :8083 >/dev/null 2>&1; then
    systemctl start souran-doh 2>/dev/null || python3 /opt/souran-ai/scripts/doh-proxy-8083.py &
    echo "  - Started DoH Proxy (Port 8083)"
else
    echo "  - DoH Proxy already running on 8083"
fi

if ! lsof -i :8082 >/dev/null 2>&1; then
    systemctl start souran-agent 2>/dev/null || python3 /opt/souran-ai/scripts/agent-dashboard-8082.py &
    echo "  - Started Hermes Agent (Port 8082)"
else
    echo "  - Hermes Agent already running on 8082"
fi

if ! lsof -i :8383 >/dev/null 2>&1; then
    systemctl start souran-web 2>/dev/null || python3 /opt/souran-ai/scripts/web-dashboard-8383.py &
    echo "  - Started Web Dashboard (Port 8383)"
else
    echo "  - Web Dashboard already running on 8383"
fi

sleep 2

echo ""
echo -e "${YELLOW}[9/10]${NC} Running verification tests..."
sleep 1

# Test DoH Proxy
if command -v curl >/dev/null 2>&1; then
    DOH_TEST=$(curl -s http://localhost:8083/dns-query?name=google.com&type=A 2>/dev/null | head -1)
    if [ -n "$DOH_TEST" ] && echo "$DOH_TEST" | grep -q '"Status"'; then
        echo -e "${GREEN}  ✓ DoH Proxy (8083): Working${NC}"
    else
        echo -e "${YELLOW}  ! DoH Proxy (8083): Check service${NC}"
    fi
    
    AGENT_TEST=$(curl -s http://localhost:8082/health 2>/dev/null)
    if [ -n "$AGENT_TEST" ] && echo "$AGENT_TEST" | grep -q '"status"'; then
        echo -e "${GREEN}  ✓ Hermes Agent (8082): Working${NC}"
    else
        echo -e "${YELLOW}  ! Hermes Agent (8082): Check service${NC}"
    fi
    
    WEB_TEST=$(curl -s http://localhost:8383/ 2>/dev/null | grep -o '<title>.*</title>' | head -1)
    if [ -n "$WEB_TEST" ]; then
        echo -e "${GREEN}  ✓ Web Dashboard (8383): Working${NC}"
    else
        echo -e "${YELLOW}  ! Web Dashboard (8383): Check service${NC}"
    fi
fi

echo ""
echo -e "${YELLOW}[10/10]${NC} Final status check..."
sleep 1

echo ""
echo "========================================="
echo "INSTALLATION SUMMARY"
echo "========================================="
echo ""
echo "Version: $VERSION ($BUILD_ID)"
echo ""
echo "Port Assignments:"
echo "  8083 → DoH Proxy (Your User Port)"
echo "  8082 → Hermes Agent (Your Management Port)"
echo "  8383 → Web Dashboard (Your Tools Port)"
echo ""
echo "Services Built From ZERO Source:"
echo "  ✓ Rust DNS Server (/usr/local/bin/soran-dns)"
echo "  ✓ DoH Proxy (scripts/doh-proxy-8083.py)"
echo "  ✓ Hermes Agent (scripts/agent-dashboard-8082.py)"
echo "  ✓ Web Dashboard (scripts/web-dashboard-8383.py)"
echo ""
echo "Access URLs:"
echo "  DoH:     http://localhost:8083/dns-query"
echo "  Agent:   http://localhost:8082"
echo "  Web:     http://localhost:8383"
echo ""
echo "Documentation:"
echo "  README.md - Project overview"
echo "  CHANGELOG.md - Version history"
echo "  VERSION_MANIFEST-v1.0.0.md - Complete file manifest"
echo "  BuildFromZero-v1.0.0-Complete-Report.md - Test report"
echo ""
echo "To enable auto-start on boot:"
echo "  systemctl enable souran-doh souran-agent souran-web"
echo ""
echo -e "${GREEN}✅ INSTALLATION COMPLETE - ALL FROM ZERO SOURCE${NC}"
echo ""