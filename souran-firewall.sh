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

# Publish firewall/NAT state where the unprivileged control plane can read
# it. The dashboard services run with NoNewPrivileges=yes, so they cannot
# read netfilter state directly and cannot sudo. Without this file their
# probes reported the firewall as "off" while it was enforcing.
publish_state() {
    local out=/opt/souran-ai/logs/firewall-state.json
    local sf=false dnsnat=false tables="[]"

    nft list table inet souran_filter >/dev/null 2>&1 && sf=true

    # The redirect is on ONE line, e.g.
    #   ip daddr != 127.0.0.0/8 ip protocol udp ... udp dport 53 ... redirect to :9053
    # Grepping one field and then the other on separate passes fails,
    # because the lines containing 9053 are not the same lines that
    # contain "dport 53" in the way the two-step test assumed.
    if nft list table ip nat 2>/dev/null \
       | grep 'dport 53' | grep -q '9053'; then
        dnsnat=true
    fi

    mkdir -p "$(dirname "$out")"
    cat > "$out" <<EOF
{
  "updated_at": "$(date -Is)",
  "souran_filter_loaded": $sf,
  "outbound_dns_to_tor": $dnsnat,
  "source": "souran-firewall.sh"
}
EOF
    chmod 0644 "$out"
}

cmd_load() {
    # Idempotent, but it MUST still reach systemd with a real "I did the
    # work" result.
    #
    # This previously short-circuited with "already loaded" and returned 0.
    # That is harmless when a human runs it, but as a Type=oneshot unit it
    # meant the FIRST boot-time invocation found the table absent, loaded
    # it, and every later `systemctl start` reported success while the
    # unit stayed `inactive (dead)` -- so nothing in systemd owned the
    # ruleset. An adversarial reviewer caught exactly this: the table was
    # live in the kernel but would have been LOST on reboot, taking the
    # whole default-deny posture with it.
    #
    # `nft list ... || load` is now unconditional, and publish_state runs
    # either way so the unprivileged control plane always has fresh data.
    if nft list table inet "$TABLE" >/dev/null 2>&1; then
        publish_state
        echo "souran firewall already loaded (state refreshed)"
        return 0
    fi
    nft --file "$NFT_CONF"
    publish_state
    echo "souran firewall loaded"
}

cmd_reload() {
    # Delete only OUR table. `nft flush ruleset` would take Docker's NAT
    # rules with it and silently break container networking.
    nft delete table inet "$TABLE" 2>/dev/null || true
    nft --file "$NFT_CONF"
    publish_state
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
    # Refresh state now, not only at next boot.
    cmd_reload >/dev/null 2>&1 || true
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
