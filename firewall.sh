#!/bin/bash
#===============================================================================
# SOURAN AI NETWORK SERVER v5.1.0 - FIREWALL HARDENING
#===============================================================================
set -euo pipefail

LOG="/var/log/souran-firewall.log"
RULES_V4="/etc/iptables/rules.v4"
RULES_V6="/etc/iptables/rules.v6"
IPTABLES="/usr/sbin/iptables"
IP6TABLES="/usr/sbin/ip6tables"

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] FIREWALL: $1" | tee -a "$LOG"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then echo "ERROR: This script must be run as root" >&2; exit 1; fi
}

flush_rules() {
    log "Flushing existing iptables rules..."
    $IPTABLES -F 2>/dev/null || true; $IPTABLES -X 2>/dev/null || true; $IPTABLES -Z 2>/dev/null || true
    $IPTABLES -t nat -F 2>/dev/null || true; $IPTABLES -t mangle -F 2>/dev/null || true
    $IP6TABLES -F 2>/dev/null || true; $IP6TABLES -X 2>/dev/null || true; $IP6TABLES -Z 2>/dev/null || true
    $IP6TABLES -t mangle -F 2>/dev/null || true
    $IPTABLES -P INPUT DROP; $IPTABLES -P FORWARD DROP; $IPTABLES -P OUTPUT ACCEPT
    log "Default policies: INPUT DROP, FORWARD DROP, OUTPUT ACCEPT"
}

allow_loopback() {
    $IPTABLES -A INPUT -i lo -j ACCEPT; $IPTABLES -A OUTPUT -o lo -j ACCEPT
    log "Loopback allowed"
}

allow_established() {
    $IPTABLES -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    log "Established/related allowed"
}

allow_ssh() {
    $IPTABLES -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set --name SSH
    $IPTABLES -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 --rttl --name SSH -j DROP
    $IPTABLES -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
    log "SSH (22) rate-limited"
}

allow_dns() {
    $IPTABLES -A INPUT -p udp --dport 53 -j ACCEPT; $IPTABLES -A INPUT -p tcp --dport 53 -j ACCEPT
    log "DNS (53) allowed"
}

allow_unbound() {
    $IPTABLES -A INPUT -p tcp --dport 5300 -j ACCEPT
    log "Unbound (5300) allowed"
}

allow_technitium() {
    $IPTABLES -A INPUT -p tcp --dport 53443 -j ACCEPT
    log "Technitium API (53443) allowed"
}

allow_tor() {
    $IPTABLES -A INPUT -p tcp --dport 9050 -j ACCEPT; $IPTABLES -A INPUT -p tcp --dport 9051 -j ACCEPT
    log "Tor (9050/9051) allowed"
}

allow_dashboards() {
    $IPTABLES -A INPUT -p tcp --dport 8080 -s 127.0.0.1 -j ACCEPT
    $IPTABLES -A INPUT -p tcp --dport 8081 -s 127.0.0.1 -j ACCEPT
    $IPTABLES -A INPUT -p tcp --dport 8082 -s 127.0.0.1 -j ACCEPT
    $IPTABLES -A INPUT -p tcp --dport 8080 -s 10.0.0.0/8 -j ACCEPT
    $IPTABLES -A INPUT -p tcp --dport 8081 -s 10.0.0.0/8 -j ACCEPT
    $IPTABLES -A INPUT -p tcp --dport 8082 -s 10.0.0.0/8 -j ACCEPT
    $IPTABLES -A INPUT -p tcp --dport 8080 -s 192.168.0.0/16 -j ACCEPT
    $IPTABLES -A INPUT -p tcp --dport 8081 -s 192.168.0.0/16 -j ACCEPT
    $IPTABLES -A INPUT -p tcp --dport 8082 -s 192.168.0.0/16 -j ACCEPT
    log "Dashboards restricted to localhost and LAN only"
}

allow_dot_doh() {
    $IPTABLES -A INPUT -p tcp --dport 853 -j ACCEPT; $IPTABLES -A INPUT -p tcp --dport 443 -j ACCEPT
    log "DoT (853) and DoH (443) allowed"
}

rate_limit_syn() {
    $IPTABLES -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
    $IPTABLES -A INPUT -p tcp --syn -j DROP
    log "SYN flood protection enabled"
}

rate_limit_port_scans() {
    $IPTABLES -A INPUT -p tcp -m multiport --dports 22,8080,8081,8082,53443,53,5300,9050,853,443 -m conntrack --ctstate NEW -m recent --set --name PORTSCAN
    $IPTABLES -A INPUT -p tcp -m multiport --dports 22,8080,8081,8082,53443,53,5300,9050,853,443 -m conntrack --ctstate NEW -m recent --update --seconds 10 --hitcount 5 --rttl --name PORTSCAN -j DROP
    log "Port scan detection: 5 hits in 10s = DROP"
}

block_bogus() {
    $IPTABLES -A INPUT -s 0.0.0.0/8 -j DROP; $IPTABLES -A INPUT -s 172.16.0.0/12 -j DROP
    $IPTABLES -A INPUT -d 224.0.0.0/4 -j DROP; $IPTABLES -A INPUT -d 255.255.255.255 -j DROP
    log "Bogon/multicast filtering enabled"
}

log_dropped() {
    $IPTABLES -A INPUT -m limit --limit 5/min -j LOG --log-prefix "FIREWALL-DROP: " --log-level 4
    log "Dropped packet logging (5/min)"
}

save_rules() {
    mkdir -p /etc/iptables
    iptables-save > "$RULES_V4" 2>/dev/null || true
    ip6tables-save > "$RULES_V6" 2>/dev/null || true
    log "Rules saved"
}

persist_service() {
    if ! systemctl is-enabled souran-iptables 2>/dev/null; then
        cat > /etc/systemd/system/souran-iptables.service <<'SVCEOF'
[Unit]
Description=Restore Souran Network Firewall Rules
After=network.target
[Service]
Type=oneshot
ExecStart=/usr/sbin/iptables-restore /etc/iptables/rules.v4
ExecStart=/usr/sbin/ip6tables-restore /etc/iptables/rules.v6
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
SVCEOF
        systemctl daemon-reload 2>/dev/null || true
        systemctl enable souran-iptables 2>/dev/null || true
        log "souran-iptables service enabled"
    fi
}

apply_rules() {
    check_root
    log "=== Starting Souran AI Firewall Hardening v5.1.0 ==="
    flush_rules
    allow_loopback; allow_established; allow_ssh; allow_dns; allow_unbound
    allow_technitium; allow_tor; allow_dashboards; allow_dot_doh
    rate_limit_syn; rate_limit_port_scans; block_bogus; log_dropped
    save_rules; persist_service
    log "=== Firewall rules applied ==="
    echo "Firewall hardened. Ports: 53 5300 53443 8080 8081 8082 9050"
    echo "See $LOG for details."
}

case "${1:-}" in
    apply) apply_rules ;;
    flush) check_root; flush_rules; save_rules ;;
    status) iptables -L -n -v 2>/dev/null || true ;;
    save) check_root; save_rules ;;
    *) apply_rules ;;
esac
