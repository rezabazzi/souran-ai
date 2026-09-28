#!/bin/bash
#===============================================================================
# SOURAN AI NETWORK SERVER v5.1.0 - AUTO WATCHDOG (UPDATED)
# 24/7 monitoring, auto-diagnosis, auto-fix, auto-health
# Zero human touch required
#
# Monitors: Technitium DNS (53), DNS API (53443), DNS Web (5380),
#           Hermes Dashboard (8082), DoH Endpoint (8083)
# No stale service references (dnsmasq, unbound, tor, cloudflared removed)
# MAX_RESTARTS prevents infinite restart loops
#===============================================================================
set -euo pipefail

LOG="/var/log/souran-ai-watchdog.log"
HEALTH="/run/souran-ai-health.json"
CACHE_DIR="/var/lib/souran-watchdog"
MAX_RESTARTS=3
CHECK_INTERVAL=30
RESTART_LOG="/run/souran-restart-counts.json"

mkdir -p "$CACHE_DIR" /var/log /run /var/lib/souran-watchdog
touch "$LOG"

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $1" | tee -a "$LOG"; }

check_port() {
    ss -lntup 2>/dev/null | grep -q ":$1 " && return 0 || return 1
}

check_dns_resolve() {
    dig @127.0.0.1 google.com +short 2>/dev/null | grep -qE '^[0-9]' && return 0 || return 1
}

check_http() {
    local url="$1" code
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url" 2>/dev/null || echo "000")
    [ "$code" -ge 200 ] && [ "$code" -lt 400 ] && return 0 || return 1
}

check_service() {
    local svc="$1"
    systemctl is-active --quiet "$svc" 2>/dev/null && return 0 || return 1
}

# Track restart counts — prevents infinite loops
get_restart_count() {
    local svc="$1"
    [ -f "$RESTART_LOG" ] || echo "{}" > "$RESTART_LOG"
    python3 -c "import json; d=json.load(open('$RESTART_LOG')); print(d.get('$svc', 0))" 2>/dev/null || echo 0
}

increment_restart_count() {
    local svc="$1"
    python3 -c "
import json, os
p='$RESTART_LOG'
d = json.load(open(p)) if os.path.exists(p) else {}
d['$svc'] = d.get('$svc', 0) + 1
json.dump(d, open(p, 'w'))
" 2>/dev/null || true
}

reset_restart_count() {
    local svc="$1"
    python3 -c "
import json
p='$RESTART_LOG'
d = json.load(open(p))
d['$svc'] = 0
json.dump(d, open(p, 'w'))
" 2>/dev/null || true
}

restart_service() {
    local svc="$1" count
    count=$(get_restart_count "$svc")
    if [ "$count" -ge "$MAX_RESTARTS" ]; then
        log "SKIP: $svc exceeded MAX_RESTARTS ($count/$MAX_RESTARTS) — manual intervention required"
        return 1
    fi
    log "RESTARTING: $svc (attempt $((count + 1))/$MAX_RESTARTS)"
    systemctl restart "$svc" 2>/dev/null
    sleep 3
    if check_service "$svc"; then
        log "OK: $svc restarted successfully"
        reset_restart_count "$svc"
    else
        increment_restart_count "$svc"
        log "FAIL: $svc restart failed (count now $(get_restart_count "$svc"))"
    fi
}

auto_health() {
    local dns_api="fail" dns_web="fail" dashboard="fail" doh="fail" dns_resolve="fail"

    # Check DNS port
    check_port 53 || log "WARN: DNS port 53 not listening"
    # Check DNS resolution
    check_dns_resolve && dns_resolve="ok" || dns_resolve="fail"

    # Check Technitium API
    local token=""
    [ -f /etc/dns/api-token.txt ] && token=$(cat /etc/dns/api-token.txt 2>/dev/null || true)
    if [ -n "$token" ]; then
        curl -sk --noproxy '*' --max-time 5 \
            -H "Authorization: Bearer $token" \
            "https://127.0.0.1:53443/api/settings/get" 2>/dev/null | \
            grep -q '"version"' && dns_api="ok" || dns_api="fail"
    fi

    # Check Technitium Web
    check_port 5380 || log "WARN: Technitium Web port 5380 not listening"
    # Check Technitium status via API
    if [ "$dns_api" = "ok" ]; then
        curl -sk --noproxy '*' --max-time 5 \
            -H "Authorization: Bearer $token" \
            "https://127.0.0.1:53443/api/dashboard/stats/get" 2>/dev/null | \
            grep -q 'totalQueries' && dns_web="ok" || dns_web="fail"
    fi

    # Check Hermes Dashboard (8082)
    check_http "http://127.0.0.1:8082/health" && dashboard="ok" || dashboard="fail"

    # Check DoH Endpoint (8083)
    check_http "http://127.0.0.1:8083/health" && doh="ok" || doh="fail"

    # Check systemd services
    local svc_dashboard=$(systemctl is-active souran-8082-dashboard 2>/dev/null || echo "unknown")
    local svc_doh=$(systemctl is-active souran-8083-doh 2>/dev/null || echo "unknown")
    local svc_dns=$(systemctl is-active souran-dns 2>/dev/null || echo "unknown")

    cat > "$HEALTH" <<EOH
{"timestamp":"$(date -u +%Y-%m-%dT%H:%M:%SZ)",
"dns_port":"$(check_port 53 && echo ok || echo fail)",
"dns_resolve":"$dns_resolve","dns_api":"$dns_api","dns_web":"$dns_web",
"dashboard":"$dashboard","dashboard_svc":"$svc_dashboard",
"doh":"$doh","doh_svc":"$svc_doh","dns_svc":"$svc_dns",
"memory":"$(free -h 2>/dev/null | awk '/Mem:/{print $3"/"$2}')",
"disk":"$(df -h / 2>/dev/null | awk 'NR==2{print $3"/"$2}')",
"uptime":"$(uptime -p 2>/dev/null || echo unknown)"}
EOH
    log "HEALTH: dns=$dns_resolve dashboard=$dashboard doh=$doh svc_dash=$svc_dashboard svc_doh=$svc_doh svc_dns=$svc_dns"
}

auto_fix() {
    local issues=""

    if ! check_dns_resolve; then issues="${issues} dns_down"; fi
    if ! check_port 53; then issues="${issues} dns_port_down"; fi
    if ! check_http "http://127.0.0.1:8082/health"; then issues="${issues} dashboard_down"; fi
    if ! check_http "http://127.0.0.1:8083/health"; then issues="${issues} doh_down"; fi

    # Restart with loop prevention
    if echo "$issues" | grep -q "dns_down\|dns_port_down"; then
        log "DIAGNOSIS: DNS resolution or port issue"
        check_service DnsServerApp 2>/dev/null || true
    fi
    if echo "$issues" | grep -q "dashboard_down"; then
        log "DIAGNOSIS: Dashboard (8082) down"
        restart_service "souran-8082-dashboard"
    fi
    if echo "$issues" | grep -q "doh_down"; then
        log "DIAGNOSIS: DoH (8083) down"
        restart_service "souran-8083-doh"
    fi

    if [ -z "$issues" ]; then
        : # All healthy — no logging needed (reduces log spam)
    fi
}

auto_rebuild() {
    local rebuild_flag="$CACHE_DIR/rebuild.flag"
    if [ -f "$rebuild_flag" ]; then
        log "AUTO-REBUILD: Triggered by rebuild.flag"
        rm -f "$rebuild_flag"
        # Restart all services as rebuild
        for svc in souran-8082-dashboard souran-8083-doh; do
            restart_service "$svc"
        done
        log "AUTO-REBUILD: Complete"
    fi
}

# Main loop
log "SOURAN AI AUTO WATCHDOG v5.1.0 STARTED — Monitoring DNS(53), API(53443), Web(5380), Dashboard(8082), DoH(8083)"
while true; do
    auto_health
    auto_fix
    auto_rebuild
    sleep "$CHECK_INTERVAL"
done
