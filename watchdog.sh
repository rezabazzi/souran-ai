#!/bin/bash
SOURAN_DIR="/opt/souran-ai"
LOG_FILE="$SOURAN_DIR/logs/watchdog.log"
mkdir -p $SOURAN_DIR/logs

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> $LOG_FILE
}

check_dns() {
    result=$(dig @127.0.0.1 google.com A +short 2>/dev/null)
    [ -n "$result" ]
}

check_tor() {
    systemctl is-active tor &>/dev/null
}

check_ports() {
    for port in 53 8082 8383 9050; do
        ss -tulpn | grep -q ":$port " || return 1
    done
    return 0
}

repair_dns() {
    log_msg "REPAIR: Restarting DNS"
    pkill -f "resolver.py" 2>/dev/null || true
    sleep 1
    python3 $SOURAN_DIR/dns/resolver.py &>/dev/null &
}

repair_tor() {
    log_msg "REPAIR: Restarting Tor"
    systemctl restart tor 2>/dev/null || true
}

while true; do
    if ! check_dns; then
        log_msg "WARN: DNS not responding"
        repair_dns
    fi
    if ! check_tor; then
        log_msg "WARN: Tor not active"
        repair_tor
    fi
    if ! check_ports; then
        log_msg "WARN: Ports not listening"
        repair_dns
        repair_tor
    fi
    log_msg "STATUS: All systems operational"
    sleep 300
done
