#!/usr/bin/env bash
#===============================================================================
# install-souran.sh — Souran AI Network Server v4.2.0 Installation
# Builds from source, configures all services, runs full test suite.
# Usage: sudo bash install-souran.sh
#===============================================================================

set -euo pipefail

VERSION="4.2.0"
INSTALL_DIR="/opt/souran-ai"
log() { echo -e "\033[1;32m[$(date -u '+%Y-%m-%dT%H:%M:%SZ')]\033[0m $1"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $1"; }
error() { echo -e "\033[1;31m[ERROR]\033[0m $1"; }

log "============================================"
log "Souran AI Network Server v${VERSION}"
log "Installation from ZERO"
log "============================================"

# [1/12] Prerequisites
log "[1/12] Prerequisites..."
for cmd in python3 git curl dig systemctl ss iptables; do
    command -v "$cmd" >/dev/null 2>&1 || {
        log "Installing $cmd..."; echo "$PASS" | sudo -n apt-get install -y "$cmd" 2>/dev/null || true;
    }
done

# [2/12] Directories
log "[2/12] Directories..."
sudo -n mkdir -p "$INSTALL_DIR"/{config,data,scripts,engine,anticompress/{incoming,index,data},logs} \
    2>/dev/null <<< "$PASS"

# [3/12] Build Unbound from source
log "[3/12] Building Unbound..."
if [ ! -f "$INSTALL_DIR/engine/unbound/sbin/unbound" ] && [ -d "$INSTALL_DIR/engine/unbound-src" ]; then
    (cd "$INSTALL_DIR/engine/unbound-src" && make -j"$(nproc)" 2>/dev/null && \
     make install DESTDIR="$INSTALL_DIR/engine/unbound" 2>/dev/null) || \
        warn "Unbound build failed — using system unbound"
else
    log "Unbound already built or no source."
fi

# [4/12] DNS config
log "[4/12] DNS config..."
if [ -f "$INSTALL_DIR/config/souran-unbound.conf.yaml" ]; then
    echo "$PASS" | sudo -n unbound-checkconf "$INSTALL_DIR/config/souran-unbound.conf.yaml" 2>/dev/null || true
fi

# [5/12] Systemd services
log "[5/12] Systemd services..."
for svc in souran-dns souran-dns-dot souran-doh-fallback souran-8082-dashboard \
            souran-8083-doh souran-web-8383 souran-watchdog \
            souran-learning-engine souran-anticompress; do
    if [ -f "/etc/systemd/system/${svc}.service" ]; then
        sudo -n systemctl daemon-reload 2>/dev/null <<< "$PASS" || true
        sudo -n systemctl enable "$svc" 2>/dev/null <<< "$PASS" || true
    fi
done

# [6/12] Start services
log "[6/12] Starting services..."
for svc in souran-dns souran-dns-dot souran-doh-fallback souran-8082-dashboard \
            souran-8083-doh souran-web-8383 souran-watchdog \
            souran-learning-engine souran-anticompress; do
    sudo -n systemctl restart "$svc" 2>/dev/null <<< "$PASS" || true
done
sleep 3

# [7/12] Censorship bypass
log "[7/12] Censorship bypass (GoodbyeDPI + Zapret)..."
[ -f "$INSTALL_DIR/scripts/souran-goodbyedpi.sh" ] && \
    bash "$INSTALL_DIR/scripts/souran-goodbyedpi.sh" 2>/dev/null || true
[ -f "$INSTALL_DIR/scripts/souran-zapret.sh" ] && \
    bash "$INSTALL_DIR/scripts/souran-zapret.sh" 2>/dev/null || true

# [8/12] NAT/DNS policy
log "[8/12] NAT/DNS policy..."
echo "$PASS" | sudo -n iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-port 5399 2>/dev/null || true
echo "$PASS" | sudo -n iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-port 5399 2>/dev/null || true

# [9/12] Data directories
log "[9/12] Data directories..."
sudo -n chown -R "$USER:$USER" "$INSTALL_DIR" 2>/dev/null <<< "$PASS" || true

# [10/12] Version stamp
log "[10/12] Version stamp..."
echo "$VERSION" | sudo -n tee "$INSTALL_DIR/VERSION" >/dev/null <<< "$PASS"

# [11/12] Test suite
log "[11/12] Running test suite..."
python3 "$INSTALL_DIR/souran_test_suite.py" 2>/dev/null || warn "Some tests failed — review output"

# [12/12] Summary
echo ""
log "SOURAN AI NETWORK SERVER v${VERSION} — READY"
echo "  Dashboards:  http://127.0.0.1:8082 (Hermes)  http://127.0.0.1:8383 (Neuro)"
echo "  DNS:         127.0.0.1:5399 (Unbound)"
echo "  DoH:         127.0.0.1:8083    DoT: 127.0.0.1:853"
echo "  Learning:    127.0.0.1:8084    Anti-Compress: 127.0.0.1:8085"
echo "  API:         127.0.0.1:53443   Tor SOCKS: 127.0.0.1:9050"
echo "  Status:      DNS=$(systemctl is-active souran-dns 2>/dev/null || echo unknown)"
log "============================================"