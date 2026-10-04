#!/usr/bin/env bash
# souran-zapret.sh — Install and configure Zapret DPI evasion
# Part of Souran AI Network Server v4.2.0

set -euo pipefail

INSTALL_DIR="/opt/souran-ai/censorship/zapret"
SRC_DIR="/opt/souran-ai/censorship/zapret/src"
CONFIG_DIR="/opt/souran-ai/censorship/config"

echo "[zapret] Installing dependencies..."
sudo -n apt-get install -y git curl wget iproute2 iptables nano \
    2>/dev/null 

echo "[zapret] Cloning from source..."
mkdir -p "$SRC_DIR"
git clone --depth 1 https://github.com/bol-van/zapret.git "$SRC_DIR" 2>/dev/null || {
    echo "[zapret] Already cloned or git unavailable"
}

echo "[zapret] Configuring..."
mkdir -p "$CONFIG_DIR"

# Default Zapret config for DPI bypass
cat > "$CONFIG_DIR/zapret-init.sh" << 'INITEOF'
#!/bin/bash
# Zapret DPI bypass configuration for Souran AI Network Server
export ZAPRET_HOSTS_FILE="$CONFIG_DIR/zapret-hosts.txt"
export ZAPRET_METHOD="nfqws"
export ZAPRET_DPI_DESYNC="split2,fake"
export ZAPRET_PORTS="80,443,8080,8443"
export ZAPRET_BYPASS_PROTOCOLS="tls,http"
INITEOF
chmod +x "$CONFIG_DIR/zapret-init.sh"

# Hosts list for DPI bypass
cat > "$CONFIG_DIR/zapret-hosts.txt" << 'HOSTSEOF'
telegram.org
instagram.com
youtube.com
x.com
reddit.com
twitter.com
facebook.com
netflix.com
whatsapp.com
signal.org
HOSTSEOF

echo "[zapret] Creating systemd service..."
cat > /tmp/souran-zapret.service << 'SVCEOF'
[Unit]
Description=Souran AI — Zapret DPI bypass
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
User=root
WorkingDirectory=/opt/souran-ai/censorship/zapret/src
ExecStartPre=/bin/bash /opt/souran-ai/censorship/config/zapret-init.sh
ExecStart=/opt/souran-ai/censorship/zapret/src/init.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SVCEOF
sudo -n cp /tmp/souran-zapret.service /etc/systemd/system/ 2>/dev/null  || true
sudo -n systemctl daemon-reload 2>/dev/null  || true
sudo -n systemctl enable souran-zapret 2>/dev/null  || true

echo "[zapret] Done — config in $CONFIG_DIR/"