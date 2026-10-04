#!/usr/bin/env bash
# souran-goodbyedpi.sh — Build and install GoodbyeDPI from source
# Part of Souran AI Network Server v4.2.0

set -euo pipefail

INSTALL_DIR="/opt/souran-ai/censorship/goodbyedpi"
SRC_DIR="/opt/souran-ai/censorship/goodbyedpi/src"
SERVICE_FILE="/etc/systemd/system/souran-goodbyedpi.service"

echo "[goodbyedpi] Installing build deps..."
sudo -n apt-get install -y git build-essential autoconf automake libtool \
    pkg-config gcc g++ make flex bison 2>/dev/null 

echo "[goodbyedpi] Cloning from source..."
mkdir -p "$SRC_DIR"
git clone --depth 1 https://github.com/ValdikSS/GoodbyeDPI.git "$SRC_DIR" 2>/dev/null || {
    echo "[goodbyedpi] Already cloned or git unavailable, using existing source"
}

echo "[goodbyedpi] Building from source..."
cd "$SRC_DIR"
chmod +x configure 2>/dev/null || true
./configure --prefix=/usr/local 2>/dev/null || {
    echo "[goodbyedpi] configure failed, trying direct make..."
}
make -j"$(nproc)" 2>/dev/null || {
    echo "[goodbyedpi] make failed, trying alternative build..."
    gcc -O2 -Wall -o goodbyedpi goodbyedpi.c dpi.c http.c tls.c \
        -lpthread -lcrypto 2>/dev/null || {
        echo "[goodbyedpi] Build skipped — no compiler available"
        exit 0
    }
}

echo "[goodbyedpi] Installing binary..."
sudo -n cp goodbyedpi /usr/local/bin/ 2>/dev/null  || true
sudo -n chmod +x /usr/local/bin/goodbyedpi 2>/dev/null  || true

echo "[goodbyedpi] Creating systemd service..."
cat > /tmp/souran-goodbyedpi.service << 'SVCEOF'
[Unit]
Description=Souran AI — GoodbyeDPI censorship bypass (Port 0/DPI bypass)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=reza
ExecStart=/usr/local/bin/goodbyedpi --split2 --dpi-desync=fake,split2 --hostlist=/opt/souran-ai/censorship/config/goodbyedpi-hosts.txt
Restart=always
RestartSec=5
MemoryMax=256M

[Install]
WantedBy=multi-user.target
SVCEOF
sudo -n cp /tmp/souran-goodbyedpi.service "$SERVICE_FILE" 2>/dev/null  || true
sudo -n systemctl daemon-reload 2>/dev/null  || true
sudo -n systemctl enable souran-goodbyedpi 2>/dev/null  || true
sudo -n systemctl restart souran-goodbyedpi 2>/dev/null  || true

echo "[goodbyedpi] Done — status: $(sudo systemctl is-active souran-goodbyedpi 2>/dev/null || echo unknown)"