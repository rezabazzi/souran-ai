#!/bin/bash
# Version: v5.1.0 | Souran AI Network Server

echo "============================================"
echo "  SOURAN AI NETWORK SERVER — DASHBOARD"
echo "============================================"
echo ""
echo "SERVICES:"
for svc in dns souran-unbound cloudflared tor souran-watchdog dnsmasq souran-ai souran-ai-watchdog; do
    status=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
    echo "  $svc: $status"
done
echo ""
echo "BINARY STATUS:"
for bin in unbound named dnsmasq; do
    path=$(which $bin 2>/dev/null || echo "NOT_FOUND")
    echo "  $bin: $path"
done
echo ""
echo "DNS RESOLUTION TEST:"
dig @127.0.0.1 google.com +short 2>/dev/null && echo "  Technitium DNS: OK" || echo "  Technitium DNS: FAIL"
echo ""
echo "HEALTH:"
cat /run/souran-ai-health.json 2>/dev/null || echo "  No health data"
echo ""
echo "WATCHDOG LOG (last 5):"
tail -5 /var/log/souran-ai-watchdog.log 2>/dev/null
echo ""
echo "FEATURES: Recursive DNS | DNSSEC | DoT | DoH | DoQ | Tor Bypass | Cloudflare Tunnel | Advanced Cache | Auto-Healing | Zero-Block"
echo "============================================"
