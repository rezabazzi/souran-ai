#!/bin/bash
# Souran AI Network Server v0.1.0 - Installation Script
# Build from source, zero upstream, complete RFC support

set -e

echo "=== Souran AI Network Server Installation v0.1.0 ==="

# Check prerequisites
echo "[1/5] Checking prerequisites..."
if ! command -v cargo &> /dev/null; then
    echo "ERROR: Rust/Cargo not installed. Please install Rust first."
    exit 1
fi

# Build from source
echo "[2/5] Building from source..."
cd /opt/soran
cargo build --release 2>&1 | tail -5

if [ ! -f target/release/soran ]; then
    echo "ERROR: Build failed"
    exit 1
fi

# Install binary
echo "[3/5] Installing binary..."
sudo cp target/release/soran /usr/local/bin/soran
sudo chmod +x /usr/local/bin/soran

# Create systemd service
echo "[4/5] Creating systemd service..."
sudo tee /etc/systemd/system/souran-dns.service > /dev/null << 'EOF'
[Unit]
Description=Souran AI DNS Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/soran dns --port 8083
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/souran-agent.service > /dev/null << 'EOF'
[Unit]
Description=Souran AI Agent Controller
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/soran agent --port 8082 --dashboard 8383
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Enable and start services
echo "[5/5] Enabling services..."
sudo systemctl daemon-reload
sudo systemctl enable souran-dns souran-agent 2>/dev/null || true

echo ""
echo "=== Installation Complete ==="
echo "DNS Server:    port 8083 (user port)"
echo "Agent Control: port 8082 (Hermes port)"
echo "Dashboard:     port 8383"
echo ""
echo "Run 'soran doctor' to verify installation"
echo "Run 'sudo systemctl start souran-dns' to start DNS server"
echo "Run 'sudo systemctl start souran-agent' to start agent controller"