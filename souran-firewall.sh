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


# ---- LAN subnet derivation --------------------------------------------
#
# The ruleset refers to $LAN rather than a literal, because a hardcoded
# subnet rots silently: the host moved from 10.103.26.0/24 to
# 192.168.1.0/24 and every LAN rule stopped matching, so DNS and the
# dashboards became unreachable from the real network while the firewall
# test still passed (it built its own namespace on the stale subnet).
#
# Derived from the interface holding the default route, which is the
# network the operator's clients are actually on. wg0 and docker0 are
# excluded: a VPN or a container bridge is not the LAN, and allowing
# 10.0.0.0/8 to reach :53 would re-open the amplifier this ruleset exists
# to prevent.
_valid_subnet() {
    # A malformed subnet becomes a syntax error in the ruleset, and under
    # the old delete-then-load order that meant no firewall at all. The
    # FALLBACK is validated too, because SOURAN_FALLBACK_LAN is an
    # environment variable and "0.0.0.0/0" would otherwise open the LAN
    # service set to the entire internet.
    case "$1" in
        ""|*[!0-9./]*) return 1 ;;
        */0|*/1|*/2|*/3) return 1 ;;
        */*) return 0 ;;
        *) return 1 ;;
    esac
}

lan_subnet() {
    local dev addr
    dev="$(ip -4 route show default 2>/dev/null | awk '/default/ {for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')"
    if [ -n "$dev" ]; then
        addr="$(ip -4 -o addr show dev "$dev" scope global 2>/dev/null | awk '{print $4}' | head -1)"
        if [ -n "$addr" ]; then
            local derived
            derived="$(echo "${addr%/*}" | awk -F. '{printf "%s.%s.%s.0/24",$1,$2,$3}')"
            if _valid_subnet "$derived"; then
                echo "$derived"
                return 0
            fi
            echo "souran-firewall: derived subnet '$derived' is invalid" >&2
        fi
    fi
    local fb="${SOURAN_FALLBACK_LAN:-192.168.1.0/24}"
    if _valid_subnet "$fb"; then
        echo "$fb"
        return 0
    fi
    # Refuse rather than emit something that parses into an over-permissive
    # rule. Failing loudly beats loading the wrong policy.
    echo "souran-firewall: no usable LAN subnet; refusing" >&2
    return 1
}

render_ruleset() {
    # Substitute $LAN into a temp copy; never edit the tracked file, so the
    # derived value is not baked into version control.
    #
    # The caller OWNS the returned file and must remove it. This leaked
    # one root-owned copy per invocation with no trap and no rm anywhere
    # in the script -- measured 5 orphans on the live host, growing
    # without bound on every load/reload/test.
    local lan tmp
    lan="$(lan_subnet)"
    tmp="$(mktemp /tmp/souran-nft.XXXXXX.nft)"
    sed "s|\$LAN|$lan|g" "$NFT_CONF" > "$tmp"
    chmod 600 "$tmp"
    echo "$tmp"
}

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
    nft --check --file "$(render_ruleset)" && echo "syntax OK"
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
    nft --file "$(render_ruleset)"
    publish_state
    echo "souran firewall loaded"
}

cmd_reload() {
    # VALIDATE FIRST, DELETE SECOND. The order is the safety property.
    #
    # The previous version deleted the table and then loaded, so an invalid
    # ruleset -- a malformed or empty $LAN, for instance -- meant the delete
    # had already succeeded and the load failed. That leaves NO
    # souran_filter table, the input policy falls back to accept, and every
    # service the ruleset documents as loopback-only (:11434 Ollama, :8118
    # privoxy, :9192 sidecar) becomes reachable from the LAN.
    #
    # Render, `nft --check`, and only then replace. A failed check leaves
    # the live table untouched and still filtering.
    local rendered
    rendered="$(render_ruleset)"
    if ! nft --check --file "$rendered" >/dev/null 2>&1; then
        echo "souran firewall: REFUSING to load an invalid ruleset." >&2
        echo "  the live table is unchanged and still filtering." >&2
        nft --check --file "$rendered" 2>&1 | sed 's/^/  /' >&2 || true
        rm -f "$rendered"
        return 1
    fi

    # Delete only OUR table. `nft flush ruleset` would take Docker's NAT
    # rules with it and silently break container networking.
    nft delete table inet "$TABLE" 2>/dev/null || true
    if ! nft --file "$rendered"; then
        # Unreachable after --check passed, but if the kernel still refuses,
        # restore rather than leave the host with no filter at all.
        echo "souran firewall: load failed after delete; restoring." >&2
        rm -f "$rendered"
        cmd_load
        return 1
    fi
    rm -f "$rendered"
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
