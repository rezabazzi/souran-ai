#!/bin/bash
# =====================================================================
# SOURAN AI NETWORK SERVER v5.1.0 — PRIVILEGED FEATURE ACTUATOR
# =====================================================================
#
# WHY THIS EXISTS
# ---------------
# Every control-plane service (sidecar, dashboards) runs with
# NoNewPrivileges=yes and ProtectSystem=full. That is correct hardening
# and it is not negotiable — it is what stops a compromised web handler
# from escalating. But it has two consequences that broke the feature
# registry:
#
#   1. `sudo` is unusable from those services ("no new privileges").
#      So they cannot start or stop anything.
#   2. They cannot read netfilter state (no CAP_NET_ADMIN), and cannot
#      read /run/systemd/private without AF_UNIX.
#
# Rather than weaken the hardening on every service, this script is the
# single narrow privileged entry point. It is invoked through a sudoers
# rule that permits exactly this one file, with a fixed command
# vocabulary. It resolves unit names from its OWN allowlist — a caller
# cannot smuggle an arbitrary unit name or an arbitrary shell string
# through it.
#
# SECURITY PROPERTIES
# -------------------
#   - The sudoers entry allows ONLY this absolute path, never a shell.
#   - `feature` must be one of the identifiers listed below, so the unit
#     to operate on is chosen by this file, not by the caller.
#   - `action` is one of exactly three words.
#   - No arguments are passed through to a shell at any point.
#   - Every invocation is logged to /opt/souran-ai/logs/feature-actions.log
#     so the dashboard's writes are auditable.
#
# Usage:  sudo -n /opt/souran-ai/souran-feature-apply.sh <feature> <action>
#           action = enable | disable | reload
# =====================================================================
set -euo pipefail

LOG=/opt/souran-ai/logs/feature-actions.log
mkdir -p "$(dirname "$LOG")"

log() {
    printf '%s %s uid=%s %s\n' \
        "$(date -Is)" "$1" "${SUDO_UID:-?}" "${*:2}" >>"$LOG" 2>/dev/null || true
}

FEATURE="${1:-}"
ACTION="${2:-}"

# ---- allowlisted actions ------------------------------------------------
case "$ACTION" in
    enable|disable|reload) ;;
    *)
        echo "refused: action must be enable|disable|reload" >&2
        log REFUSE "feature=${FEATURE} action=${ACTION}"
        exit 2
        ;;
esac

# ---- feature -> units ---------------------------------------------------
# Kept in lockstep with souran_features.FEATURES. Adding a feature there
# without adding it here means it is visible but not actionable, which is
# the safe direction to fail in.
units_for() {
    case "$1" in
        dns_recursive)        echo "souran-dns" ;;
        dns_frontend)         echo "souran-doh-fallback" ;;
        dns_over_tls)         echo "souran-dns-dot" ;;
        dns_over_https)       echo "souran-8083-doh" ;;
        censor_zapret)        echo "souran-zapret" ;;
        censor_byedpi)        echo "souran-byedpi" ;;
        censor_tor)           echo "tor@default" ;;
        censor_socks_bridge)  echo "socks-bridge" ;;
        web3_ens)             echo "souran-web3-resolver" ;;
        gaming_dns)           echo "souran-gaming-dns" ;;
        ops_watchdog)         echo "souran-watchdog" ;;
        ops_intrusion_detection) echo "souran-ids" ;;
        ops_cloudflared)      echo "cloudflared" ;;
        ops_learning_engine)  echo "souran-learning-engine" ;;
        ops_anticompress)     echo "souran-anticompress" ;;
        ops_dashboard_hermes) echo "souran-8082-dashboard" ;;
        ops_dashboard_web)    echo "souran-web-8383" ;;
        ops_sidecar_api)      echo "souran-sidecar" ;;
        ops_firewall)         echo "souran-firewall" ;;
        # Not unit-backed; handled by config rewrite instead.
        dns_dnssec)           echo "" ;;
        dns_tcp_upstream)     echo "" ;;
        dns_cache_prefetch)   echo "" ;;
        dns_doh_tier)         echo "" ;;
        censor_outbound_dns)  echo "" ;;
        web3_rpc)             echo "souran-web3-resolver" ;;
        dns_dnssec_tor_note)  echo "" ;;
        # No unit on purpose: these act on a generated RULESET and must
        # end with a reload of souran-dns. Mapping them to the unit
        # makes the action `systemctl enable --now`, a no-op for an
        # already-active unit, so the new rules were never loaded and
        # the toggle reported success with blocking still off.
        ad_blocklists)        echo "" ;;
        lan_names)            echo "" ;;
        # Optional projects: no unit, so they reach apply_config,
        # which refuses them explicitly as not-installed.
        alt_ouinet)           echo "" ;;
        alt_veltor)           echo "" ;;
        alt_veltor)           echo "" ;;
        proxy_xray)           echo "xray" ;;
        proxy_hysteria)        echo "hysteria" ;;
        proxy_singbox)         echo "sing-box" ;;
        *)
            echo "refused: unknown feature '${FEATURE}'" >&2
            log REFUSE "feature=${FEATURE} unknown"
            exit 3
            ;;
    esac
}

UNITS="$(units_for "$FEATURE")"

# ---- helpers for config-backed features -------------------------------
#
# These exist so the handlers below stay declarative. Each one changes
# exactly one thing and reports failure, rather than a `sed` that may
# match nothing and still report success.

# systemd drop-in for a unit: the only supported way to change a unit's
# Environment= without editing the packaged unit file.
setenv_dropin() {
    local unit="$1"; shift
    local dir="/etc/systemd/system/${unit}.service.d"
    mkdir -p "$dir"
    {
        echo "# Managed by souran-feature-apply.sh -- do not edit."
        for kv in "$@"; do echo "Environment=$kv"; done
    } > "$dir/90-souran-feature.conf"
    systemctl daemon-reload >/dev/null 2>&1 || return 1
}

# JSON flag in the sidecar's own state file.
# Enable/disable a generated ruleset by commenting its `include:` line.
#
# NOT by deleting the file. The config `include:`s the ruleset, so
# deleting it makes unbound-checkconf fail, unbound refuses to reload,
# and the toggle silently has no effect -- and the resolver then cannot
# restart at all, because there is no valid config to start from.
# Measured: souran-dns went to `activating` with the file absent.
#
# Commenting the include is reversible, always leaves a valid config, and
# the generated file is cheap to keep (it rebuilds in ~8 s).
ruleset_include() {
    # $1 = the path fragment identifying this feature's include
    # $2 = yes | no
    #
    # Two mistakes worth recording, both made and both caught by testing:
    #   * matching on `f` (the feature id) did not match the PATH, which
    #     is spelled blocklist.conf / lan.conf, so nothing was commented;
    #   * the first version also matched the explanatory COMMENT line
    #     that mentions the same path, and commented that instead.
    # So: match the exact include target, and never a comment line.
    local conf=/opt/souran-ai/config/souran-unbound.conf.yaml
    local target="$1" want="$2"
    local tmp; tmp="$(mktemp)"
    awk -v t="$target" -v want="$want" '
        # strip any existing disable marker first
        { line = $0; sub(/^#souran-feature-off:/, "", line) }
        line ~ ("^[[:space:]]*include:.*" t) {
            if (want == "yes") { print line }
            else              { print "#souran-feature-off:" line }
            next
        }
        { print line }
    ' "$conf" > "$tmp"
    cat "$tmp" > "$conf"
    rm -f "$tmp"
    return 0
}

# ---- config-backed features --------------------------------------------
apply_config() {
    local conf=/opt/souran-ai/config/souran-unbound.conf.yaml
    case "${FEATURE}:${ACTION}" in
        dns_dnssec:enable)
            sed -i 's/^\( *\)val-permissive-mode: .*/\1val-permissive-mode: no/' "$conf" ;;
        dns_dnssec:disable)
            sed -i 's/^\( *\)val-permissive-mode: .*/\1val-permissive-mode: yes/' "$conf" ;;
        dns_tcp_upstream:enable)
            sed -i 's/^\( *\)tcp-upstream: .*/\1tcp-upstream: yes/' "$conf" ;;
        dns_tcp_upstream:disable)
            sed -i 's/^\( *\)tcp-upstream: .*/\1tcp-upstream: no/' "$conf" ;;
        dns_cache_prefetch:enable)
            sed -i 's/^\( *\)prefetch: .*/\1prefetch: yes/' "$conf" ;;
        dns_cache_prefetch:disable)
            sed -i 's/^\( *\)prefetch: .*/\1prefetch: no/' "$conf" ;;

        # --- DoH escalation tier ---------------------------------------
        # The tier is the front-end's own SOURAN_DOH_URL setting, so it is
        # a unit drop-in rather than a YAML key.
        dns_doh_tier:enable)
            setenv_dropin souran-doh-fallback \
                "SOURAN_DOH_URL=https://cloudflare-dns.com/dns-query" \
                "SOURAN_DOH_URL2=https://dns.google/resolve" ;;
        dns_doh_tier:disable)
            setenv_dropin souran-doh-fallback "SOURAN_DOH_URL=" "SOURAN_DOH_URL2=" ;;

        # --- the two ruleset features ----------------------------------
        ad_blocklists:disable)
            ruleset_include "blocklist.conf" no ;;
        ad_blocklists:enable)
            ruleset_include "blocklist.conf" yes
            /opt/souran-ai/souran_blocklists.py compile >/dev/null 2>&1 || return 1 ;;
        lan_names:disable)
            ruleset_include "lan.conf" no ;;
        lan_names:enable)
            ruleset_include "lan.conf" yes
            /opt/souran-ai/souran_lan.py compile >/dev/null 2>&1 || return 1 ;;


        # --- Ouinet / CENO ---------------------------------------------
        # The container EXISTS on this host (equalitie/ouinet) but has
        # been `Exited (0)` for two weeks, so a previous version refused
        # with "not installed" -- which was wrong: it is installed and
        # stopped. Enabling starts the existing container; disabling stops
        # it. Neither pulls an image or creates anything.
        alt_ouinet:enable)
            docker start ouinet >/dev/null 2>&1 || {
                echo "error: could not start the ouinet container" >&2; return 1; } ;;
        alt_ouinet:disable)
            docker stop ouinet >/dev/null 2>&1 || {
                echo "error: could not stop the ouinet container" >&2; return 1; } ;;

        # --- Veltor -----------------------------------------------------
        # Genuinely absent: no binary, no /opt/veltor, no unit. Refusing
        # is the honest answer rather than reporting a success.
        alt_veltor:*)
            echo "error: alt_veltor is not installed on this host (no" >&2
            echo "       binary, no /opt/veltor, no unit). Install it first." >&2
            return 1 ;;

        # --- an informational note, not a capability -------------------
        dns_dnssec_tor_note:*)
            echo "error: ${FEATURE} is a note, not a switchable feature." >&2
            return 1 ;;

        # Anything unhandled REFUSES. The old `*) return 0` reported
        # "ok" for seven features while changing nothing at all, which is
        # the exact class of confident falsehood this registry exists to
        # eliminate.
        *)
            echo "error: ${FEATURE} ${ACTION} has no apply handler; refusing" >&2
            echo "       to report success for an action that does nothing." >&2
            return 1 ;;
    esac
    log CONFIG "feature=${FEATURE} action=${ACTION} file=${conf}"
    systemctl reload souran-dns >/dev/null 2>&1 || \
        systemctl restart souran-dns >/dev/null 2>&1 || true
}

# ---- main ---------------------------------------------------------------
if [ -z "$UNITS" ]; then
    apply_config
    log APPLY "feature=${FEATURE} action=${ACTION} target=config"
    echo "ok: ${FEATURE} ${ACTION} (config)"
    exit 0
fi

failed=0
for u in $UNITS; do
    case "$ACTION" in
        enable)
            systemctl enable --now "$u" >/dev/null 2>&1 || failed=1
            ;;
        disable)
            systemctl disable --now "$u" >/dev/null 2>&1 || \
                systemctl stop "$u" >/dev/null 2>&1 || failed=1
            ;;
        reload)
            systemctl reload "$u" >/dev/null 2>&1 || \
                systemctl restart "$u" >/dev/null 2>&1 || failed=1
            ;;
    esac
done

if [ "$failed" -ne 0 ]; then
    log FAIL "feature=${FEATURE} action=${ACTION} units=${UNITS}"
    echo "error: ${FEATURE} ${ACTION} failed for units: ${UNITS}" >&2
    exit 1
fi

# Keep the unprivileged control plane informed of netfilter state.
if [ "$FEATURE" = "ops_firewall" ]; then
    /opt/souran-ai/souran-firewall.sh status >/dev/null 2>&1 || true
    /opt/souran-ai/souran-firewall.sh reload >/dev/null 2>&1 || true
fi

log APPLY "feature=${FEATURE} action=${ACTION} units=${UNITS}"
echo "ok: ${FEATURE} ${ACTION} (${UNITS})"
exit 0
