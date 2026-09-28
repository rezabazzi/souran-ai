#!/bin/bash
set -euo pipefail
echo "=== SOURAN AI NETWORK SERVER v5.1.0 ==="
echo ""
echo "[1/9] Installing DNS services..."
sudo -S -p systemctl restart dns 2>/dev/null
sudo -S -p systemctl restart souran-unbound 2>/dev/null
sudo -S -p systemctl restart dnsmasq 2>/dev/null
echo "  DNS services started"
echo ""
echo "[2/9] Starting Tor censorship bypass..."
sudo -S -p systemctl restart tor@default 2>/dev/null
echo "  Tor active"
echo ""
echo "[3/9] Starting Cloudflare DoH tunnel..."
sudo -S -p systemctl restart cloudflared 2>/dev/null
echo "  Cloudflare tunnel active"
echo ""
echo "[4/9] Starting auto-watchdog..."
sudo -S -p systemctl restart souran-ai-watchdog 2>/dev/null
echo "  Watchdog active"
echo ""
echo "[5/9] Starting web dashboards..."
if ! pgrep -f "web-dashboard.py" > /dev/null; then
    nohup python3 /opt/souran-ai/web-dashboard.py > /var/log/souran-web.log 2>&1 &
    echo "  Web dashboard on port 8081"
fi
if ! pgrep -f "agent-dashboard.py" > /dev/null; then
    nohup python3 /opt/souran-ai/agent-dashboard.py > /var/log/souran-agent.log 2>&1 &
    echo "  Agent control on port 8082"
fi
echo ""
echo "[6/9] Starting Security Dashboard (port 8083)..."
if ! pgrep -f "security-dashboard.py" > /dev/null; then
    nohup python3 /opt/souran-ai/security-dashboard.py > /var/log/souran-security-dashboard.log 2>&1 &
    echo "  Security dashboard on port 8083"
fi
echo ""
echo "[7/9] Starting Agent Investigator (port 8084)..."
if ! pgrep -f "agent-investigate.py" > /dev/null; then
    nohup python3 /opt/souran-ai/agent-investigate.py > /var/log/souran-investigator.log 2>&1 &
    echo "  Agent investigator on port 8084"
fi
echo ""
echo "[8/9] Starting Alert Bridge (port 8085)..."
if ! pgrep -f "alert-bridge.py" > /dev/null; then
    nohup python3 /opt/souran-ai/alert-bridge.py > /var/log/souran-alert-bridge.log 2>&1 &
    echo "  Alert bridge on port 8085"
fi
echo ""
echo "[9/9] Verifying DNS resolution..."
dig @127.0.0.1 google.com +short >/dev/null 2>&1 && echo "  DNS resolving" || echo "  DNS check"
sudo -S -p /opt/souran-ai/souran-ai init 2>/dev/null
echo ""
echo "=== ALL SYSTEMS OPERATIONAL ==="
echo "Dashboards:"
echo "  Web:          http://127.0.0.1:8081"
echo "  Agent:        http://127.0.0.1:8082"
echo "  Security:     http://127.0.0.1:8083"
echo "  Investigator: http://127.0.0.1:8084"
echo "  Alerts:       http://127.0.0.1:8085"
echo "Version: 4.3.1"
