#!/bin/bash
# Souran v5.1.0 — firewall control.
#
# Loads config/souran-firewall.nft. Idempotent, and SAFE by construction:
# this script never flushes the nat table, because the outbound DNS→Tor
# redirect (:9053) and the cloudflared 7844→:17844 redirect live there and
# are what make censorship bypass work at all.
set -euo pipefail

NFT_CONF="/opt/souran-ai/config/souran-firewall.nft"
TABLE="souran_filter"

usage() {
    cat <<'EOF'
usage: souran-firewall.sh {load|reload|status|test|save}

  load    load the ruleset if not already present
  reload  remove and re-add the souran_filter table (atomic swap)
  status  show the current ruleset and a per-port reachability summary
  test    verify the syntax without applying anything
  save    ensure the rules are re-applied on boot
EOF
}

cmd_test() {
    nft --check --file "$NFT_CONF" && echo "syntax OK"
}

cmd_load() {
    if nft list table inet "$TABLE" >/dev/null 2>&1; then
        echo "souran firewall already loaded"
        return 0
    fi
    nft --file "$NFT_CONF"
    echo "souran firewall loaded"
}

cmd_reload() {
    # Delete only OUR table. `nft flush ruleset` would take Docker's NAT
    # rules with it and silently break container networking.
    nft delete table inet "$TABLE" 2>/dev/null || true
    nft --file "$NFT_CONF"
    echo "souran firewall reloaded"
}

cmd_save() {
    local unit=/etc/systemd/system/souran-firewall.service
    cat > "$unit" <<EOF
[Unit]
Description=Souran host firewall (nftables)
Documentation=file:/opt/souran-ai/config/souran-firewall.nft
After=network-pre.target
Before=network.target docker.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/opt/souran-ai/souran-firewall.sh load
ExecReload=/opt/souran-ai/souran-firewall.sh reload

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable souran-firewall.service >/dev/null 2>&1 || true
    echo "souran-firewall.service installed and enabled"
}

cmd_status() {
    echo "=== souran_filter ruleset ==="
    nft list table inet "$TABLE" 2>/dev/null || echo "(not loaded)"
    echo
    echo "=== input policy ==="
    nft list table inet "$TABLE" 2>/dev/null \
        | grep -m1 'hook input' || true
    echo
    echo "=== NAT table preserved (censorship bypass depends on it) ==="
    nft list table ip nat 2>/dev/null | grep -E 'dport 53|dport 7844' || true
    echo
    echo "=== listening ports and their exposure ==="
    ss -tulpnH 2>/dev/null | awk '{print $1, $5}' | sort -u -k2 | while read -r proto addr; do
        case "$addr" in
            127.0.0.1:*|\[::1\]:*) scope="loopback-only" ;;
            0.0.0.0:*|\[::\]:*|*:*)    scope="ALL-INTERFACES" ;;
            *)                          scope="specific" ;;
        esac
        printf "  %-5s %-22s %s\n" "$proto" "$addr" "$scope"
    done | sort -k3
}

case "${1:-}" in
    load)   cmd_load ;;
    reload) cmd_reload ;;
    status) cmd_status ;;
    test)   cmd_test ;;
    save)   cmd_save ;;
    *)      usage; exit 2 ;;
esac
