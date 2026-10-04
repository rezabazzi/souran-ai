#!/bin/bash
#=================================================================================
# Souran Network Auto Watchdog v4 — Comprehensive Edition
# Auto-diagnose + auto-fix + auto-restart + auto-rebuild for the full DNS/
# censorship stack, with per-feature ON/OFF kill switches (hot-reload).
#
# Monitors : Technitium DNS, Unbound, BIND9, CoreDNS, PowerDNS, cloudflared,
#            Tor, nginx, privoxy, WireGuard, xray, hysteria, sing-box, dnstt,
#            zapret, socks-bridge, dashboard :8080, sidecar, dhcp, serveo,
#            DNS protocols (UDP/53, DoT, DoH, DoQ, DoH3), censorship bypass,
#            censorship probe, dns_cache, dnssec, shadowsocks, iptables,
#            self-health, disk pressure, config guard, resource watch,
#            auto-build on source changes.
# Fixes    : service restarts, NAT rule re-apply, circuit-breaker half-open,
#            disk pressure (journal vacuum + stale log purge), config snapshots,
#            SOURCE REBUILD on git changes, DNS engine-specific repair.
# Alerts   : ntfy.sh + healthchecks.io dead-man's-switch (gated by FEATURE_alerts)
# Control  : features.conf (see /etc/souran-watchdog/features.conf) or `wd-ctl`
# CLI      : wd-ctl check|check --fix|feature <n> <on|off>|features|logs [N]|
#            reset <comp>|version|build|status|status-json|run
# Zero-Block: enableBlocking=false, blockListUrls empty, no RPZ, no reject routes.
#            This watchdog never touches blocking configuration.
#===============================================================================

set -Eeuo pipefail
IFS=$'\n\t'
SCRIPT_VERSION="4.0.0"

# ── Paths ──────────────────────────────────────────────────────────
FEATURES_FILE="${FEATURES_FILE:-/etc/souran-watchdog/features.conf}"
CIRCUIT_BREAKER_FILE="/var/lib/souran-watchdog/circuit-breaker.json"
STATUS_FILE="/var/lib/souran-watchdog/status.json"
RUN_STATUS_FILE="/run/souran-watchdog-status.json"
STATE_DIR="/var/lib/souran-watchdog"
LOG_DIR="/var/log/souran-watchdog"
BACKUP_DIR="/var/backups/souran-dns"
SOURCE_DIR="/home/reza/Projects/Linux-Setup"
LOG_FILE="${LOG_DIR}/watchdog_$(date '+%Y-%m-%d').log"
LOCK_FILE="/run/souran-watchdog.lock"
PID=$$

# ── Defaults (overridable via env or features.conf) ──────────────────────────
NTFY_URL="${NTFY_URL:-https://ntfy.sh/souran-dell-alerts}"
HEALTHCHECKS_URL="${HEALTHCHECKS_URL:-https://hc-ping.com/f3b84b71-5011-48df-8675-5f856e1c57e3}"
HEALTHCHECKS_FAIL="${HEALTHCHECKS_FAIL:-https://hc-ping.com/f3b84b71-5011-48df-8675-5f856e1c57e3/fail}"
TUNNEL_ID="${TUNNEL_ID:-876fc02b-e1af-4df6-8cba-ba21b6bf75ee}"
CF_ZONE="${CF_ZONE:-mordaddns.ir}"
MYSQL_HOST="${MYSQL_HOST:-127.0.0.1}"
MYSQL_PORT="${MYSQL_PORT:-3306}"
MYSQL_USER="${MYSQL_USER:-souran}"
MYSQL_PASS="${MYSQL_PASS:-Reza654321}"
MYSQL_DB="${MYSQL_DB:-DnsQueryLogs}"
TEST_DOMAIN="${TEST_DOMAIN:-telegram.org}"
API_TOKEN_FILE="/etc/dns/api-token.txt"
DASHBOARD_PORT="${DASHBOARD_PORT:-8080}"
CF_METRICS_PORT="${CF_METRICS_PORT:-20241}"
CHECK_INTERVAL="${CHECK_INTERVAL:-120}"
MAX_RESTART_ATTEMPTS="${MAX_RESTART_ATTEMPTS:-3}"
STARTUP_GRACE="${STARTUP_GRACE:-30}"
BREAKER_COOLDOWN_S="${BREAKER_COOLDOWN_S:-900}"
RESTART_WINDOW_S="${RESTART_WINDOW_S:-3600}"
RESTART_MAX_PER_WINDOW="${RESTART_MAX_PER_WINDOW:-3}"
MEM_ALERT_PCT="${MEM_ALERT_PCT:-90}"
MEM_FIX_PCT="${MEM_FIX_PCT:-85}"
DISK_ALERT_PCT="${DISK_ALERT_PCT:-90}"
DISK_VACUUM_PCT="${DISK_VACUUM_PCT:-80}"
CACHE_MIN_RATIO="${CACHE_MIN_RATIO:-0.005}"
CACHE_MIN_ENTRIES="${CACHE_MIN_ENTRIES:-0}"
CACHE_MIN_HITS_HOURLY="${CACHE_MIN_HITS_HOURLY:-0}"
CACHE_WARMUP_S="${CACHE_WARMUP_S:-3600}"
CACHE_FLUSH_COOLDOWN_S="${CACHE_FLUSH_COOLDOWN_S:-3600}"
PROBE_MIN_INTERVAL="${PROBE_MIN_INTERVAL:-1800}"
UPLINK_TTL="${UPLINK_TTL:-60}"
AUTO_BUILD_INTERVAL="${AUTO_BUILD_INTERVAL:-300}"
BUILD_COOLDOWN_S="${BUILD_COOLDOWN_S:-120}"

# ── Build tracking state ───────────────────────────────────────────
BUILD_STATE_FILE="$STATE_DIR/.build_state"
BUILD_LAST_TS_FILE="$STATE_DIR/.build_last_ts"
BUILD_LOCK_FILE="$STATE_DIR/.build_lock"

# ── Colours ────────────────────────────────────────────────────────
SRED='\033[0;31m'; SGREEN='\033[0;32m'
SYELLOW='\033[1;33m'; SBLUE='\033[0;34m'; SNOC='\033[0m'

# ══════════════════════════════════════════════════════════════════════════════
# UTILITY
# ══════════════════════════════════════════════════════════════════════════════

log() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] [$1] [PID:$PID] ${*:2}" | tee -a "$LOG_FILE" 2>/dev/null || true; }
log_info()  { log "INFO" "$@"; }
log_warn()  { log "${SYELLOW}WARN${SNOC}" "$@"; }
log_error() { log "${SRED}ERROR${SNOC}" "$@"; }
log_ok()    { log "${SGREEN} OK ${SNOC}" "$@"; }
log_alert() { log "${SRED}ALERT${SNOC}" "$@"; }
log_build() { log "${SBLUE}BUILD${SNOC}" "$@"; }

init_dirs() {
  mkdir -p "$LOG_DIR" "$STATE_DIR" "$BACKUP_DIR" 2>/dev/null || true
  chmod 755 "$LOG_DIR" "$STATE_DIR" 2>/dev/null || true
}

acquire_lock() {
  if [[ -f "$LOCK_FILE" ]] && kill -0 "$(cat "$LOCK_FILE" 2>/dev/null)" 2>/dev/null; then
    log_warn "Another instance running (PID: $(cat $LOCK_FILE)) — exiting"
    exit 0
  fi
  echo "$PID" > "$LOCK_FILE"
}
release_lock() { rm -f "$LOCK_FILE"; }

jq_available() { command -v jq &>/dev/null; }

acquire_build_lock() {
  local tries=0
  while [[ $tries -lt 5 ]]; do
    if [[ ! -f "$BUILD_LOCK_FILE" ]] || ! kill -0 "$(cat "$BUILD_LOCK_FILE" 2>/dev/null)" 2>/dev/null; then
      echo "$$" > "$BUILD_LOCK_FILE"
      return 0
    fi
    sleep 1; tries=$((tries+1))
  done
  log_warn "  [Build] could not acquire build lock — skipping"
  return 1
}
release_build_lock() { rm -f "$BUILD_LOCK_FILE"; }

# ══════════════════════════════════════════════════════════════════════════════
# FEATURE FLAGS  (features.conf, hot-reloaded every cycle)
# ══════════════════════════════════════════════════════════════════════════════

declare -A FEATURE_MAP=()
declare -A DISABLED_NOTED=()
_AUTOFIX_OVERRIDE=""

load_features() {
  FEATURE_MAP=()
  [[ -f "$FEATURES_FILE" ]] && while IFS='=' read -r k v; do
    k="${k%%#*}"; k="${k// /}"; v="${v// /}"; v="${v%%#*}"
    [[ -z "$k" ]] && continue
    case "$k" in
      FEATURE_*) FEATURE_MAP["${k#FEATURE_}"]="$v" ;;
      MEM_ALERT_PCT|DISK_ALERT_PCT|DISK_VACUUM_PCT)
        [[ "$v" =~ ^[0-9]+$ ]] && eval "${k}=${v}" ;;
      CHECK_INTERVAL|MAX_RESTART_ATTEMPTS|STARTUP_GRACE|BREAKER_COOLDOWN_S|RESTART_WINDOW_S|RESTART_MAX_PER_WINDOW|AUTO_BUILD_INTERVAL|BUILD_COOLDOWN_S)
        [[ "$v" =~ ^[0-9]+$ ]] && eval "${k}=${v}" ;;
    esac
  done < <(grep -vE '^[[:space:]]*(#|$)' "$FEATURES_FILE" 2>/dev/null | tr -d '\r' || true)
  [[ -n "$_AUTOFIX_OVERRIDE" ]] && FEATURE_MAP["auto_fix"]="$_AUTOFIX_OVERRIDE"
  return 0
}

# All known feature names
ALL_FEATURES=(technitium unbound bind9 coredns powerdns mysql dashboard \
socks_bridge cloudflared wireguard tor dns_cache zapret xray hysteria \
singbox dnstt nginx privoxy sidecar serveo dns_protocols \
censorship_bypass censorship_probe self auto_fix alerts daily_report \
resource_watch disk_repair config_guard dnssec shadowsocks \
iptables_integrity auto_build build_result)

_fkey() { echo "${1//-/_}"; }
feature_enabled() { [[ "${FEATURE_MAP[$(_fkey "$1")]:-on}" == "on" ]]; }

# Component → systemd unit
unit_for() {
  case "$1" in
    technitium) echo dns ;; unbound) echo souran-dns ;; bind9) echo named ;;
    coredns) echo coredns ;; powerdns) echo pdns ;; mysql) echo mysql ;;
    cloudflared) echo cloudflared ;; tor) echo tor ;;
    socks_bridge) echo socks-bridge ;; wireguard) echo wg-quick@wg0 ;;
    zapret) echo zapret ;; xray) echo xray ;; hysteria) echo hysteria ;;
    dnstt) echo dnstt ;; nginx) echo nginx ;; privoxy) echo privoxy ;;
    sidecar) echo dashboard-api ;; singbox) echo sing-box ;;
    serveo) echo serveo-tunnel ;; shadowsocks) echo shadowsocks-libev ;;
    *) echo "" ;;
  esac
}

sync_unit_for_feature() {
  local name="$1" val="$2" unit
  unit=$(unit_for "$name")
  [[ -z "$unit" ]] && return 0
  if [[ "$val" == "off" ]] && systemctl is-enabled --quiet "$unit" 2>/dev/null; then
    systemctl disable --now "$unit" 2>/dev/null && log_info "  [Feature] $name=off → disabled $unit" || true
  elif [[ "$val" == "on" ]] && ! systemctl is-enabled --quiet "$unit" 2>/dev/null; then
    systemctl enable --now "$unit" 2>/dev/null && log_info "  [Feature] $name=on → enabled $unit" || true
  fi
}

reconcile_units() {
  local f
  for f in "${ALL_FEATURES[@]}"; do
    [[ -n "$(unit_for "$f")" ]] || continue
    sync_unit_for_feature "$f" "${FEATURE_MAP[$f]:-on}"
  done
}

# Alerting/heartbeat
send_alert() {
  local comp="$1" msg="$2" pri="${3:-high}" tags="${4:-warning,homelab}"
  log_error "ALERT [$comp]: $msg"
  feature_enabled alerts || return 0
  curl -s --retry 2 -m 8 "$NTFY_URL" \
    -H "Title: [Souran] $comp" -H "Priority: $pri" -H "Tags: $tags" \
    -d "[$(hostname)] $msg" &>/dev/null || true
  curl -s --retry 1 -m 8 "$HEALTHCHECKS_FAIL" &>/dev/null || true
}
send_heartbeat() { feature_enabled alerts || return 0; curl -s --retry 2 -m 8 "$HEALTHCHECKS_URL" &>/dev/null || true; }
send_report() {
  feature_enabled alerts || return 0
  curl -s --retry 2 -m 10 -X POST "$NTFY_URL" \
    -H "Title: [Souran] Daily Report $(hostname) $(date '+%Y-%m-%d')" \
    -H "Priority: low" -H "Tags: chart_with_upwards_trend,dns" \
    -d "$1" &>/dev/null || true
}

# ══════════════════════════════════════════════════════════════════════════════
# JSON STATE
# ══════════════════════════════════════════════════════════════════════════════

get_state() {
  local j=''; [[ -f "$CIRCUIT_BREAKER_FILE" ]] && j=$(cat "$CIRCUIT_BREAKER_FILE" 2>/dev/null)
  printf '%s' "$j" | jq -e 'type=="object"' >/dev/null 2>&1 && printf '%s' "$j" || echo '{}'
}
_save_state() { jq_available || return 0
  printf '%s' "$1" | jq -e 'type=="object"' >/dev/null 2>&1 || return 0
  echo "$1" > "$CIRCUIT_BREAKER_FILE"; }

get_fail_count() { jq_available && echo "$(get_state)" | jq -r ".\"${1}_fail_count\" // 0" || echo 0; }
get_breaker() { jq_available && echo "$(get_state)" | jq -r ".\"${1}_breaker\" // false" || echo false; }
_update_component() {
  local c="$1" fc="$2" br="$3" ts; ts=$(date -Iseconds)
  if jq_available; then
    _save_state "$(echo "$(get_state)" | jq --arg cc "$c" --argjson f "$fc" --argjson b "$br" --arg t "$ts" \
      '.[$cc + "_fail_count"] = $f | .[$cc + "_breaker"] = $b | .[$cc + "_last_failure"] = $t')"
  fi
}
clear_component() {
  local c="$1"
  if jq_available; then
    _save_state "$(echo "$(get_state)" | jq "del(.\"${c}_fail_count\", .\"${c}_breaker\", .\"${c}_last_failure\")")"
  fi
}

declare -A RESULT=()
CYCLE_TS=""; CYCLE_NUM=""

# ══════════════════════════════════════════════════════════════════════════════
# NETWORK HELPERS
# ══════════════════════════════════════════════════════════════════════════════

check_tcp() { timeout "${3:-3}" bash -c "echo >/dev/tcp/$1/$2" 2>/dev/null; }
check_svc() {
  # A unit that is not installed is NOT unhealthy — it is absent, and the
  # correct answer is "nothing to monitor here".
  #
  # v4.3.1 bug: this was `systemctl is-active --quiet "$1"`, so every optional
  # component whose unit is not present on this host (dnsmasq, dashboard-api,
  # dnstt, serveo-tunnel) reported UNHEALTHY on every 120 s cycle, tripped
  # the restart-rate breaker ("3 restarts in 60min - hard OPEN"), and counted
  # toward the "N component(s) unhealthy" total. The watchdog was generating
  # alarms for software that was deliberately never installed, and its
  # auto-fix could not ever succeed.
  #
  # Exit codes: 0 active, 3 unit file not found / not installed.
  # Distinguishing those keeps a genuinely FAILED unit alarming while a
  # non-existent one is simply skipped.
  local state
  state=$(systemctl is-active "$1" 2>/dev/null)
  # Determine "is this unit even installed?" FIRST, because `systemctl
  # is-active` reports plain "inactive" (not "not-found") for a unit name that
  # has no unit file at all, so a state-based switch alone cannot tell
  # "installed but stopped" from "never installed".
  #
  # "Bad" state means the unit FILE exists but does not resolve — this host has
  # /etc/systemd/system/dnsmasq.service as a dangling symlink whose target is
  # gone. `list-unit-files` still prints a line for it, so grepping that would
  # misclassify it. Checking that FragmentPath resolves is the reliable test.
  local frag
  frag=$(systemctl show "$1" -p FragmentPath --value 2>/dev/null)
  if [[ -z "$frag" || ! -e "$frag" ]]; then
    return 2         # not installed (or dangling symlink): nothing to monitor
  fi

  case "$state" in
    active) return 0 ;;
    *)      return 1 ;;   # installed but inactive/failed: a genuine fault
  esac
}
# require_svc <unit> <label>: tri-state wrapper around check_svc.
#   0 = active      -> continue
#   2 = not installed -> propagate 2 so run_check() records "absent" and skips
#   1 = failed      -> log the label and return 1
#
# Why this exists: every call site used `check_svc X || { log_warn ...; return 1; }`.
# That discards check_svc's exit code, so a unit that is simply NOT INSTALLED
# (exit 2) became indistinguishable from a genuinely FAILED unit (exit 1) and
# alarmed forever. dnsmasq, dashboard-api, dnstt and serveo-tunnel are all
# absent on this host and produced a permanent false "UNHEALTHY" plus a tripped
# restart-rate breaker on every cycle.
require_svc() {
  local unit="$1" label="$2" rc=0
  check_svc "$unit" || rc=$?
  if [[ $rc -eq 2 ]]; then
    return 2
  fi
  [[ $rc -eq 0 ]] && return 0
  log_warn "  $label"
  return 1
}
resolve_domain() { dig @127.0.0.1 +time=10 +tries=2 +noedns "$1" A +short 2>/dev/null | tail -1; }

# Uplink probe (cached)
UPLINK="" UPLINK_TS=0
uplink_ok() {
  # v4.3.1 bug: the probe was `check_tcp 1.1.1.1 443` OR `ping 8.8.8.8`. On this
  # network BOTH are censored — plain TCP/443 to a Cloudflare IP is DPI-reset
  # and ICMP to 8.8.8.8 is dropped — so the probe reported UPLINK DOWN while
  # DNS, privoxy and Tor were all working. The result is a shared cache
  # (UPLINK_TTL), so one bad probe then suppressed auto-fix for EVERY
  # component ("uplink DOWN — remediation suppressed"), masking all real repair.
  #
  # The probe must test paths that are actually expected to work here:
  # the local resolver, the bypass proxy, Tor, or plain route presence.
  local now; now=$(date +%s)
  if [[ -z "$UPLINK" ]] || (( now - UPLINK_TS >= UPLINK_TTL )); then
    if dig @127.0.0.1 -p 53 +time=4 +tries=1 +short example.com A 2>/dev/null \
         | grep -qE '^[0-9]+\.'; then
      UPLINK="yes"
    elif curl -s -o /dev/null --max-time 6 \
              --proxy "${SOURAN_PROXY:-http://127.0.0.1:8118}" \
              https://1.1.1.1/ 2>/dev/null; then
      UPLINK="yes"
    elif curl -s -o /dev/null --max-time 8 --socks5-hostname 127.0.0.1:9050 \
              https://1.1.1.1/ 2>/dev/null; then
      UPLINK="yes"
    elif ip route 2>/dev/null | grep -q '^default'; then
      # A default route exists and the resolver answers; treat as up. Without
      # this, a network that only permits proxied egress (the normal case here)
      # would permanently look "DOWN" and block all auto-repair.
      UPLINK="yes"
    else
      UPLINK="no"
    fi
    UPLINK_TS=$now
  fi
  [[ "$UPLINK" == "yes" ]]
}

# Per-component restart-RATE limiter
_restart_rate_ok() {
  local comp="$1" now; now=$(date +%s)
  local f="$STATE_DIR/.restarts_${comp}" ts kept=0
  touch "$f" 2>/dev/null || return 0
  : > "${f}.tmp" 2>/dev/null || return 0
  while read -r ts; do
    [[ "$ts" =~ ^[0-9]+$ ]] || continue
    (( now - ts < RESTART_WINDOW_S )) && { echo "$ts" >> "${f}.tmp"; kept=$((kept+1)); }
  done < "$f"
  mv "${f}.tmp" "$f" 2>/dev/null || true
  if (( kept >= RESTART_MAX_PER_WINDOW )); then
    log_error "  $comp: $kept restarts in $((RESTART_WINDOW_S/60))min window - hard OPEN"
    send_alert "$comp" "Restart-rate limit hit ($kept/${RESTART_WINDOW_S}s) - auto-fix suspended" "urgent"
    return 1
  fi
  echo "$now" >> "$f"
  return 0
}

# ══════════════════════════════════════════════════════════════════════════════
# AUTO-BUILD SYSTEM — rebuild on source changes
# ══════════════════════════════════════════════════════════════════════════════

_get_source_hash() {
  if [[ ! -d "$SOURCE_DIR/.git" ]]; then
    find "$SOURCE_DIR" -maxdepth 2 -name '*.sh' -o -name '*.py' -o -name '*.cs' -o -name '*.config' 2>/dev/null | sort | xargs sha256sum 2>/dev/null | sha256sum | cut -d' ' -f1
  else
    (cd "$SOURCE_DIR" && git rev-parse HEAD 2>/dev/null || echo "none")
  fi
}

_check_source_changed() {
  local current_hash stored_hash now last_ts
  current_hash=$(_get_source_hash)
  now=$(date +%s)
  last_ts=$(cat "$BUILD_LAST_TS_FILE" 2>/dev/null || echo 0)
  stored_hash=$(cat "$BUILD_STATE_FILE" 2>/dev/null || echo "")

  if [[ -n "$last_ts" ]] && (( now - last_ts < BUILD_COOLDOWN_S )); then
    return 1
  fi
  if [[ "$current_hash" != "$stored_hash" ]]; then
    log_build "  [AutoBuild] source changed! stored=$stored_hash current=$current_hash"
    return 0
  fi
  return 1
}

_do_build() {
  acquire_build_lock || return 1
  local now=$(date +%s)
  local build_ok=1

  log_build "═══ Source Change Detected — Starting Auto-Build ═══"

  # Pull latest source
  (
    cd "$SOURCE_DIR" 2>/dev/null || { log_build "  [Build] SOURCE_DIR not accessible"; release_build_lock; return 1; }
    git stash 2>/dev/null || true
    git pull --ff-only 2>&1 | while IFS= read -r line; do log_build "  [Build] $line"; done
    git fetch origin 2>/dev/null && git reset --hard origin/HEAD 2>/dev/null || true
  )

  # Determine what changed
  local changed_files=()
  if [[ -d "$SOURCE_DIR/.git" ]]; then
    local last_commit
    last_commit=$(cat "$BUILD_STATE_FILE" 2>/dev/null || echo "")
    if [[ -n "$last_commit" ]] && [[ "$last_commit" != "none" ]]; then
      mapfile -t changed_files < <(cd "$SOURCE_DIR" && git diff --name-only "$last_commit" HEAD 2>/dev/null | head -20 || echo "")
    fi
  fi

  local needs_csharp=0 needs_config=0 needs_script=0 needs_docker=0
  for mod in "${changed_files[@]}"; do
    case "$mod" in
      *.cs|*.csproj|*.sln) needs_csharp=1 ;;
      *.sh|*.py) needs_script=1 ;;
      *.json|*.config|*.yml|*.yaml|*.toml|dns/*|etc/dns/*) needs_config=1 ;;
      docker/*|Dockerfile*) needs_docker=1 ;;
    esac
  done

  # Deploy updated scripts
  if [[ "$needs_script" -eq 1 ]]; then
    log_build "  [Build] deploying scripts..."
    cp "$SOURCE_DIR/souran-watchdog.sh" /opt/souran-watchdog/souran-watchdog.sh 2>/dev/null || true
    cp "$SOURCE_DIR/dashboard-smoke-test.sh" /opt/souran/bin/dashboard-smoke-test.sh 2>/dev/null || true
    cp "$SOURCE_DIR/dashboard-api.py" /opt/souran/bin/dashboard-api.py 2>/dev/null || true
    cp "$SOURCE_DIR/souran-singbox-rules.sh" /opt/souran/bin/souran-singbox-rules.sh 2>/dev/null || true
    cp "$SOURCE_DIR/souran-dpi-profile.sh" /opt/souran/bin/souran-dpi-profile.sh 2>/dev/null || true
    cp "$SOURCE_DIR/souran-censorship-probe.sh" /opt/souran/bin/souran-censorship-probe.sh 2>/dev/null || true
    cp "$SOURCE_DIR/dns-nat-fix.sh" /opt/souran/bin/dns-nat-fix.sh 2>/dev/null || true
  fi

  # C# rebuild
  if [[ "$needs_csharp" -eq 1 ]]; then
    log_build "  [Build] C# project changed — rebuilding..."
    (
      cd "$SOURCE_DIR/Dev-Repos/DnsServer/SouranApps/SouranDashboardApp" 2>/dev/null || true
      dotnet build -c Release 2>&1 | while IFS= read -r line; do log_build "  [Build] $line"; done
      if [[ -d "bin/Release" ]]; then
        cp bin/Release/SouranDashboardApp.dll /etc/dns/apps/SouranDashboardApp/ 2>/dev/null || true
        cp bin/Release/SouranDashboardApp.deps.json /etc/dns/apps/SouranDashboardApp/ 2>/dev/null || true
        cp bin/Release/SouranDashboardApp.runtimeconfig.json /etc/dns/apps/SouranDashboardApp/ 2>/dev/null || true
      fi
    )
    systemctl restart dns 2>/dev/null || true
    sleep 5
  fi

  # DNS config update
  if [[ "$needs_config" -eq 1 ]]; then
    log_build "  [Build] DNS config updated — reloading..."
    cp "$SOURCE_DIR/dns.conf" /etc/dns/dns.conf 2>/dev/null || true
    cp "$SOURCE_DIR/allowed.config" /etc/dns/allowed.config 2>/dev/null || true
    cp "$SOURCE_DIR/auth.config" /etc/dns/auth.config 2>/dev/null || true
    if systemctl is-active --quiet dns; then
      systemctl reload dns 2>/dev/null || { systemctl restart dns 2>/dev/null || true; }
      sleep 8
    fi
  fi

  # Docker rebuild
  if [[ "$needs_docker" -eq 1 ]]; then
    log_build "  [Build] Docker images changed — rebuilding..."
    (cd "$SOURCE_DIR" && docker-compose build --force-rm 2>&1) 2>/dev/null || true
    (cd "$SOURCE_DIR" && docker-compose up -d --no-deps 2>&1) 2>/dev/null || true
  fi

  # Verify
  sleep 3
  check_svc dns || { log_build "  [Build] dns.service not healthy"; build_ok=0; }
  check_tcp 127.0.0.1 53 || { log_build "  [Build] port 53 not open"; build_ok=0; }
  check_tcp 127.0.0.1 "$DASHBOARD_PORT" || { log_build "  [Build] dashboard not healthy"; build_ok=0; }

  local new_hash; new_hash=$(_get_source_hash)
  _update_build_state "$now" "$new_hash"

  if [[ "$build_ok" -eq 1 ]]; then
    log_build "  [Build] auto-build completed successfully"
    record build_result healthy
    send_alert "AutoBuild" "Source change detected — rebuild completed successfully" "low"
  else
    log_build "  [Build] auto-build had issues"
    record build_result unhealthy
    send_alert "AutoBuild" "Source change detected — rebuild had issues, investigate" "high"
  fi

  release_build_lock
  return $((1 - build_ok))
}

_update_build_state() {
  echo "$1" > "$BUILD_LAST_TS_FILE"
  echo "$2" > "$BUILD_STATE_FILE"
}

# ══════════════════════════════════════════════════════════════════════════════
# HEALTH CHECKS — All DNS Engines
# ══════════════════════════════════════════════════════════════════════════════

_technitium_token() { [[ -r "$API_TOKEN_FILE" ]] && head -1 "$API_TOKEN_FILE" | tr -d '\r\n '; }

check_technitium() {
  require_svc dns "  [Technitium] service not active" || return $?
  check_tcp 127.0.0.1 53 || { log_warn "  [Technitium] port 53 not open"; return 1; }
  local ip; ip=$(resolve_domain "${TEST_DOMAIN}")
  if [[ -z "$ip" || "$ip" == "timed out" ]]; then
    ip=$(resolve_domain "google.com")
    [[ -z "$ip" ]] && { log_warn "  [Technitium] DNS query failed"; return 1; }
  fi
  # Zero-block enforcement check
  local token; token=$(_technitium_token)
  if [[ -n "$token" ]]; then
    local blocking
    blocking=$(curl -sk --noproxy '*' --max-time 5 "https://127.0.0.1:53443/api/settings/get?token=$token" 2>/dev/null | jq -r '.response.enableBlocking // null' 2>/dev/null)
    [[ "$blocking" == "true" ]] && { log_warn "  [Technitium] ZERO-BLOCK VIOLATION: enableBlocking=true"; return 1; }
  fi
  log_ok "  [Technitium] OK → $ip (zero-block: enforced)"
}

fix_technitium() {
  log_warn "  [Fix] restart dns.service"
  systemctl restart dns; sleep 8
  check_svc dns && check_tcp 127.0.0.1 53 && { log_ok "  [Fix] Technitium restart OK"; return 0; }
  systemctl stop dns; sleep 2; systemctl start dns; sleep 10
  check_tcp 127.0.0.1 53 && log_ok "  [Fix] Technitium force-restart OK" || log_error "  [Fix] Technitium still failing"
  [[ "$(check_tcp 127.0.0.1 53 && echo 1)" == "1" ]]
}

# ---------------------------------------------------------------------------
# v4.0.0 — poison-proof resolution tier (front-end on :53, unbound on :5353)
#
# The architecture changed: :53 is now served by souran-doh-fallback, which
# asks unbound (tier 1, zero-upstream, :5353) and escalates to DoH when the
# answer is missing or injected. Checking port 53 alone is NOT sufficient —
# a poisoned answer looks like a healthy service, which is exactly how this
# outage hid for 22 hours. So we verify actual content, and treat a private
# answer as a fault.
# ---------------------------------------------------------------------------
POISON_RE='^(10\.|127\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|0\.)'

resolve_is_poisoned() {
  local domain="${1:-telegram.org}" answer
  answer=$(dig +time=20 +tries=1 @127.0.0.1 "$domain" A 2>/dev/null \
           | sed -n '/ANSWER SECTION:/,$p' \
           | grep -E '[[:space:]]IN[[:space:]]+A[[:space:]]' \
           | awk '{print $NF}')
  [ -z "$answer" ] && return 2
  echo "$answer" | grep -qE "$POISON_RE"
}

check_poison_dns() {
  local svc="souran-doh-fallback"
  if ! check_svc "$svc"; then
    log_warn "  [PoisonDNS] $svc not active"; return 1
  fi
  check_tcp 127.0.0.1 53 || { log_warn "  [PoisonDNS] :53 not open"; return 1; }

  local domain answer
  for domain in example.com telegram.org instagram.com; do
    answer=$(dig +time=20 +tries=1 @127.0.0.1 "$domain" A 2>/dev/null \
             | sed -n '/ANSWER SECTION:/,$p' \
             | grep -E '[[:space:]]IN[[:space:]]+A[[:space:]]' \
             | awk '{print $NF}' | head -1)
    if [ -z "$answer" ]; then
      log_warn "  [PoisonDNS] $domain returned no answer"; return 1
    fi
    if echo "$answer" | grep -qE "$POISON_RE"; then
      log_error "  [PoisonDNS] $domain resolved to injected $answer"
      return 2
    fi
  done
  log_ok "  [PoisonDNS] :53 answering, no injected addresses"
  return 0
}

fix_poison_dns() {
  log_warn "  [Fix] restart poison-proof tier"
  systemctl restart souran-doh-fallback 2>/dev/null; sleep 4
  systemctl restart souran-dns 2>/dev/null; sleep 4
  check_poison_dns >/dev/null 2>&1
}

check_unbound() {
  # v4.3.4: this used to test service "souran-unbound" on port 5300. Neither
  # exists on this host — the real zero-upstream core is souran-dns on 5399 —
  # so the check could never be anything but a false pass (require_svc treats an
  # absent unit as optional, so it silently skipped). A monitor that cannot fail
  # is worse than none, because it reports "healthy" for a tier that performs
  # no work.
  #
  # It now tests the real unit/port and distinguishes two very different states
  # that must never be conflated:
  #   - process listening but unable to RECURSE (expected here: outbound UDP/53
  #     to authorities is blocked, so tier 2 DoH carries all real traffic)
  #   - not running at all (a genuine fault)
  check_svc souran-dns 2>/dev/null || { log_warn "  [Unbound] souran-dns not active"; return 1; }
  check_tcp 127.0.0.1 5399 3 || { log_warn "  [Unbound] :5399 not open"; return 1; }

  local ans; ans=$(dig +short +time=8 +tries=1 @127.0.0.1 -p 5399 example.com A 2>/dev/null | head -1)
  if [[ -n "$ans" ]]; then
    log_ok "  [Unbound] tier-1 RECURSING directly (:5399, ${ans})"
    return 0
  fi

  # Listening but not recursing. Not a fault on this network — report it
  # honestly as informational so nobody "fixes" it by restarting the resolver.
  local nft; nft=$(sudo nft list chain ip nat OUTPUT 2>/dev/null | grep -c 'skuid 993' || echo 0)
  log_info "  [Unbound] :5399 up but cannot recurse (outbound UDP/53 blocked;"
  log_info "  [Unbound]   Tor-exempt uid 993 rule present=$nft). Tier 2 DoH is serving."
}

fix_unbound() {
  log_warn "  [Fix] restart souran-dns"
  systemctl restart souran-dns; sleep 5
  check_svc souran-dns && check_tcp 127.0.0.1 5399 && { log_ok "  [Fix] tier-1 up"; return 0; }
  log_error "  [Fix] tier-1 still failing"
  [[ "$(check_svc souran-dns && echo 1)" == "1" ]]
}

check_bind9() {
  local active=0
  check_svc named 2>/dev/null && { active=1; } || check_svc bind9 2>/dev/null && { active=1; }
  [[ "$active" -eq 0 ]] && { log_warn "  [BIND9] named/bind9 service not active"; return 1; }
  check_tcp 127.0.0.1 53 || { log_warn "  [BIND9] port 53 not open"; return 1; }
  if command -v named-checkconf &>/dev/null; then
    named-checkconf 2>/dev/null || { log_warn "  [BIND9] config syntax error"; return 1; }
  fi
  log_ok "  [BIND9] OK"
}

fix_bind9() {
  log_warn "  [Fix] restart BIND9"
  systemctl restart named 2>/dev/null || systemctl restart bind9 2>/dev/null || true
  sleep 5; check_bind9 && { log_ok "  [Fix] BIND9 OK"; return 0; }
  log_error "  [Fix] BIND9 still failing"
  [[ "$(check_bind9 && echo 1)" == "1" ]]
}

check_coredns() {
  require_svc coredns "  [CoreDNS] coredns service not active" || return $?
  check_tcp 127.0.0.1 53 || { log_warn "  [CoreDNS] port 53 not open"; return 1; }
  local code; code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://127.0.0.1:9153/health 2>/dev/null || echo "000")
  if [[ "$code" == "200" ]]; then
    log_ok "  [CoreDNS] OK (health 200, prometheus :9153)"
  elif check_tcp 127.0.0.1 53; then
    log_ok "  [CoreDNS] OK (DNS :53 responding)"
  else
    log_warn "  [CoreDNS] health endpoint failed"; return 1
  fi
}

fix_coredns() {
  log_warn "  [Fix] restart CoreDNS"
  systemctl restart coredns 2>/dev/null || true
  sleep 5
  check_coredns && { log_ok "  [Fix] CoreDNS OK"; return 0; }
  if docker ps 2>/dev/null | grep -q coredns; then
    docker restart coredns 2>/dev/null || true; sleep 5
  fi
  check_coredns && { log_ok "  [Fix] CoreDNS OK (container restart)"; return 0; }
  log_error "  [Fix] CoreDNS still failing"
  [[ "$(check_coredns && echo 1)" == "1" ]]
}

check_powerdns() {
  require_svc pdns "  [PowerDNS] pdns service not active" || return $?
  check_tcp 127.0.0.1 53 || { log_warn "  [PowerDNS] port 53 not open"; return 1; }
  check_tcp 127.0.0.1 8082 2 || { log_warn "  [PowerDNS] :8082 API not open"; return 1; }
  local code; code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://127.0.0.1:8082/api/v1/servers/localhost/statistics 2>/dev/null || echo "000")
  if [[ "$code" =~ ^(200|401)$ ]]; then
    log_ok "  [PowerDNS] OK (API :8082, DNS :53)"
  elif check_tcp 127.0.0.1 53; then
    log_ok "  [PowerDNS] OK (DNS :53 responding)"
  else
    log_warn "  [PowerDNS] API health check failed"; return 1
  fi
}

fix_powerdns() {
  log_warn "  [Fix] restart PowerDNS"
  systemctl restart pdns 2>/dev/null || true
  sleep 5; check_powerdns && { log_ok "  [Fix] PowerDNS OK"; return 0; }
  log_error "  [Fix] PowerDNS still failing"
  [[ "$(check_powerdns && echo 1)" == "1" ]]
}

check_mysql() {
  require_svc mysql "  [MySQL] service not active" || return $?
  check_tcp "$MYSQL_HOST" "$MYSQL_PORT" || { log_warn "  [MySQL] port not open"; return 1; }
  if command -v mysql &>/dev/null; then
    local rows
    rows=$(mysql -h"$MYSQL_HOST" -P"$MYSQL_PORT" -u"$MYSQL_USER" -p"$MYSQL_PASS" --silent --skip-column-names -e "SELECT COUNT(*) FROM ${MYSQL_DB}.dns_logs;" 2>/dev/null)
    [[ "$rows" =~ ^[0-9]+$ ]] && log_ok "  [MySQL] OK — $rows dns_logs rows" || { log_warn "  [MySQL] query failed"; return 1; }
  else
    log_ok "  [MySQL] OK"
  fi
}

fix_mysql() {
  log_warn "  [Fix] restart MySQL"; systemctl restart mysql; sleep 8
  check_svc mysql && { log_ok "  [Fix] MySQL OK"; return 0; }
  log_error "  [Fix] MySQL failed"
  [[ "$(check_svc mysql && echo 1)" == "1" ]]
}

check_dashboard() {
  check_tcp 127.0.0.1 "$DASHBOARD_PORT" 3 || { log_warn "  [Dashboard] port not open"; return 1; }
  local code; code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 --noproxy '*' "http://127.0.0.1:${DASHBOARD_PORT}/" 2>/dev/null)
  [[ "$code" =~ ^(200|401)$ ]] && { log_ok "  [Dashboard] HTTP $code"; return 0; }
  log_warn "  [Dashboard] HTTP $code"; return 1
}

fix_dashboard() {
  log_warn "  [Fix] restart dns.service (hosts dashboard)"
  systemctl restart dns; sleep 10
  check_tcp 127.0.0.1 "$DASHBOARD_PORT" && { log_ok "  [Fix] Dashboard OK"; return 0; }
  log_error "  [Fix] Dashboard still failing"
  [[ "$(check_tcp 127.0.0.1 "$DASHBOARD_PORT" && echo 1)" == "1" ]]
}

check_cloudflared() {
  require_svc cloudflared "  [Cloudflared] service not active" || return $?
  if check_tcp 127.0.0.1 "$CF_METRICS_PORT" 2; then
    local r; r=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "http://127.0.0.1:${CF_METRICS_PORT}/ready" 2>/dev/null || echo 000)
    [[ "$r" == "200" ]] && log_ok "  [Cloudflared] metrics /ready OK" || { log_warn "  [Cloudflared] metrics HTTP $r"; return 1; }
  elif command -v cloudflared &>/dev/null; then
    local info; info=$(cloudflared tunnel info "$TUNNEL_ID" 2>/dev/null) || true
    echo "$info" | grep -q "CONNECTOR ID" && log_ok "  [Cloudflared] tunnel connector registered" || log_warn "  [Cloudflared] tunnel info unavailable"
  fi
  log_ok "  [Cloudflared] healthy"
}

fix_cloudflared() {
  log_warn "  [Fix] restart Cloudflared"
  systemctl restart cloudflared 2>/dev/null || true; sleep 10
  check_cloudflared && { log_ok "  [Fix] Cloudflared OK"; return 0; }
  log_error "  [Fix] Cloudflared still failing"
  [[ "$(check_cloudflared && echo 1)" == "1" ]]
}

check_tor() {
  require_svc tor "  [Tor] service not active" || return $?
  check_tcp 127.0.0.1 9050 3 || { log_warn "  [Tor] SOCKS port not open"; return 1; }
  if check_tcp 127.0.0.1 9051 2; then
    local resp; resp=$(echo -e "AUTHENTICATE\r\nGETINFO status/circuit-established\r\nQUIT\r\n" | nc -w 3 127.0.0.1 9051 2>/dev/null | grep "circuit-established" || echo "")
    echo "$resp" | grep -q "circuit-established=1" && log_ok "  [Tor] circuit established" || log_info "  [Tor] bootstrapping"
  fi
  log_ok "  [Tor] healthy"
}

fix_tor() {
  log_warn "  [Fix] restart Tor"; systemctl restart tor; sleep 15
  check_svc tor && check_tcp 127.0.0.1 9050 3 && { log_ok "  [Fix] Tor OK"; return 0; }
  log_error "  [Fix] Tor still failing"
  [[ "$(check_svc tor && echo 1)" == "1" ]]
}

# Read unbound's live counters over its control socket (127.0.0.1:8953).
# Returns the raw `key=value` lines, or nothing when unbound is unreachable.
# This helper did not exist in v4.3.1 even though check_dns_cache called it, so
# the cache check could only ever report "stats unavailable".
UNBOUND_BIN="/opt/souran-ai/engine/unbound/sbin"
UNBOUND_CONF_FILE="/opt/souran-ai/config/souran-unbound.conf.yaml"
_unbound_stats() {
  [[ -x "$UNBOUND_BIN/unbound-control" ]] || return 1
  [[ -r "$UNBOUND_CONF_FILE" ]] || return 1
  "$UNBOUND_BIN/unbound-control" -c "$UNBOUND_CONF_FILE" stats 2>/dev/null
}

check_dns_cache() {
  # v4.3.1 bug: this queried the Technitium API on :53443 for cache stats.
  # Technitium was replaced by the Souran resolver, so nothing listens on
  # 53443 any more and the check reported "[DnsCache] stats API unreachable"
  # on every cycle — a permanent false alarm for a component that is actually
  # the healthiest part of the stack.
  #
  # The real cache is now: unbound (msg-cache-size 256m, rrset 512m) on :5399
  # plus the front-end's own cache in souran-doh-fallback.py on :53. Measure
  # those instead, and keep the poison canary, which is the part that matters.

  # 1) unbound control socket must answer.
  local stats_out
  stats_out=$(_unbound_stats 2>/dev/null)
  if [[ -z "$stats_out" ]]; then
    log_warn "  [DnsCache] unbound-control stats unavailable"
    return 1
  fi

  # 2) the front-end cache must actually serve a repeated query quickly.
  local t0 t1 first second
  t0=$(date +%s%N)
  first=$(dig @127.0.0.1 -p 53 +time=9 +tries=1 +short example.com A 2>/dev/null | head -1)
  t1=$(date +%s%N)
  second=$(dig @127.0.0.1 -p 53 +time=9 +tries=1 +short example.com A 2>/dev/null | head -1)
  if [[ -z "$first" || -z "$second" ]]; then
    log_warn "  [DnsCache] resolver returned no answer for cache probe"
    return 1
  fi
  if [[ "$first" != "$second" ]]; then
    log_warn "  [DnsCache] unstable answers ($first vs $second)"
    return 1
  fi
  local first_ms=$(( (t1 - t0) / 1000000 ))

  # 3) poison canary: a random .example.com must never resolve to a routable
  #    address. This is the property that actually matters for correctness.
  local probe="zz${RANDOM}${RANDOM}.example.com" panswer
  panswer=$(dig @127.0.0.1 -p 53 "$probe" A +noall +answer +time=9 +tries=1 2>/dev/null \
            | awk '{print $NF}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
  if [[ -n "$panswer" ]]; then
    log_warn "  [DnsCache] POISONING CANARY TRIPPED ($panswer)"
    return 1
  fi

  local hits
  hits=$(printf '%s' "$stats_out" | grep -m1 '^total.num.cachehits=' | cut -d= -f2)
  log_ok "  [DnsCache] OK (front-end ${first_ms}ms, cachehits=${hits:-n/a}, canary clean)"
}

_mysql_cache_hits_hour() {
  command -v mysql >/dev/null 2>&1 || { echo -1; return; }
  local r
  r=$(mysql -h"$MYSQL_HOST" -P"$MYSQL_PORT" -u"$MYSQL_USER" -p"$MYSQL_PASS" "$MYSQL_DB" -N -e "SELECT COUNT(*) FROM dns_logs WHERE response_type=3 AND timestamp>DATE_SUB(UTC_TIMESTAMP(),INTERVAL 1 HOUR);" 2>/dev/null | head -1)
  [[ "$r" =~ ^[0-9]+$ ]] && echo "$r" || echo -1
}

fix_dns_cache() {
  local token; token=$(_technitium_token)
  [[ -z "$token" ]] && { systemctl restart dns; sleep 12; return 0; }
  local api="https://127.0.0.1:53443/api"
  if ! printf '%s' "$(curl -sk --noproxy '*' --max-time 8 "$api/dashboard/stats/get?token=${token}&type=LastHour" 2>/dev/null)" | jq -e '.status=="ok"' >/dev/null 2>&1; then
    log_warn "  [Fix][DnsCache] stats API dead - restarting dns.service"
    systemctl restart dns; sleep 12; return 0
  fi
  curl -sk --noproxy '*' --max-time 5 -X POST "$api/cache/delete?token=${token}&domain=example.com" >/dev/null 2>&1
  sleep 2
  curl -sk --noproxy '*' --max-time 5 -X POST "$api/cache/flush?token=${token}&type=All" >/dev/null 2>&1
  sleep 3; check_dns_cache
}

check_socks_bridge() {
  require_svc socks-bridge "  [SocksBridge] service not active" || return $?
  check_tcp 127.0.0.1 17844 2 || { log_warn "  [SocksBridge] :17844 not open"; return 1; }
  check_tcp 127.0.0.1 8119 2 || { log_warn "  [SocksBridge] :8119 not open"; return 1; }
  if ! iptables -t nat -S OUTPUT 2>/dev/null | grep -q -- '--to-ports 17844'; then
    log_warn "  [SocksBridge] NAT redirect missing — re-applying"
    iptables -t nat -A OUTPUT -p tcp -d 198.41.128.0/17 --dport 7844 -m owner '!' --uid-owner 65534 -j REDIRECT --to-ports 17844
    iptables-save > /etc/iptables/rules.v4
  fi
  log_ok "  [SocksBridge] OK"
}

fix_socks_bridge() {
  log_warn "  [Fix] restart socks-bridge"
  check_tcp 127.0.0.1 9050 2 || { systemctl restart tor; sleep 12; }
  systemctl restart socks-bridge; sleep 3
  systemctl restart cloudflared; sleep 12
  check_socks_bridge
}

check_wireguard() {
  require_svc wg-quick@wg0 "  [WireGuard] wg-quick@wg0 not active" || return $?
  ss -ulnp 2>/dev/null | grep -q ':51820 ' && { log_ok "  [WireGuard] OK (UDP :51820)"; return 0; }
  log_warn "  [WireGuard] UDP :51820 not bound"; return 1
}

# v4.3.1 bug: run_check was called with "check_wireguard_peers", which was never
# defined anywhere in the script. Every cycle logged
#   souran-watchdog.sh: line 1241: check_wireguard_peers: command not found
# then treated the non-zero status as a fault, so "WireGuard Peers" was
# permanently UNHEALTHY with an auto-fix that could never run.
# A tunnel with zero peers is a valid, intentional state (server-only or a
# peer that has not dialled in yet), so this reports health from the interface
# and peer count instead of failing on an empty peer list.
check_wireguard_peers() {
  require_svc wg-quick@wg0 "  [WireGuardPeers] wg-quick@wg0 not active" || return $?
  local peers
  peers=$(wg show wg0 peers 2>/dev/null | grep -c '^' || true)
  peers=${peers:-0}
  if [[ "$peers" =~ ^[0-9]+$ ]] && (( peers > 0 )); then
    log_ok "  [WireGuardPeers] OK (${peers} peer(s) configured)"
    return 0
  fi
  # No peers is not a fault for a self-hosted tunnel; surface it as info.
  log_info "  [WireGuardPeers] no peers configured (server-ready)"
  return 0
}

fix_wireguard() {
  log_warn "  [Fix] restart wg-quick@wg0"; systemctl restart wg-quick@wg0; sleep 4; check_wireguard
}

_dns_proto_enabled() {
  local token; token=$(_technitium_token); [[ -z "$token" ]] && return 0
  local v
  v=$(curl -sk --noproxy '*' --max-time 5 "https://127.0.0.1:53443/api/settings/get?token=$token" 2>/dev/null | jq -r ".response.\"$1\" // true" 2>/dev/null)
  [[ "$v" == "false" ]] && return 1 || return 0
}

check_dns_protocols() {
  log_info "  [DNS-Protocols] checking all transports..."
  local all_ok=true
  local dnsb64; dnsb64=$(python3 -c "
import base64,struct
q=struct.pack('>HHHHHH',0x9999,0x0100,1,0,0,0)
for p in '${TEST_DOMAIN}'.split('.'): q+=bytes([len(p)])+p.encode()
q+=b'\x00\x00\x01\x00\x01'
print(base64.urlsafe_b64encode(q).decode().rstrip('='))" 2>/dev/null)

  if [[ -n "$(resolve_domain "${TEST_DOMAIN}")" ]]; then log_ok "    UDP DNS/53: OK"
  else sleep 5; if [[ -n "$(resolve_domain "${TEST_DOMAIN}")" ]]; then log_ok "    UDP DNS/53: OK (retry)"
  else log_warn "    UDP DNS/53: FAILED"; all_ok=false; fi; fi

  if ! _dns_proto_enabled enableDnsOverTls; then log_info "    DoT TLS/853: disabled — skipped"
  else local dot; dot=$(dig @127.0.0.1 +tls +time=12 +tries=1 "${TEST_DOMAIN}" A +short 2>/dev/null | tail -1)
  if [[ -n "$dot" && "$dot" != "failed" ]]; then log_ok "    DoT TLS/853: OK → $dot"
  else log_warn "    DoT TLS/853: FAILED"; all_ok=false; fi; fi

  # v4.3.1 bugs: this probed "https://dns.mordad/dns-query" with
  # --resolve to 127.0.0.1:443. Nothing has ever listened on 443 on this
  # host — the user DoH endpoint is the souran-8083-doh service on :8083 — so
  # "DoH HTTPS/443: FAILED" was permanent, and because one failed transport
  # sets all_ok=false, the whole "DNS Protocols" component was UNHEALTHY every
  # cycle even though UDP/53 and DoT/853 were both fine.
  local doh_code
  # Probe the JSON GET that :8083 actually implements. Two earlier versions of
  # this check were wrong: it used the RFC 8484 wire-format GET (?dns=<b64url>)
  # which this service does not implement (422), and the public-endpoint probe
  # concatenated `curl ... || echo 000` so a failure produced the nonsense code
  # "000000". Use the documented parameter form and a single fallback token.
  doh_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
    -H "Accept: application/dns-json" \
    "http://127.0.0.1:8083/dns-query?name=${TEST_DOMAIN}&type=A" 2>/dev/null)
  [[ "$doh_code" =~ ^[0-9]{3}$ ]] || doh_code="000"
  [[ "$doh_code" == "200" ]] && log_ok "    DoH HTTP/8083 (RFC 8484): OK" \
    || { log_warn "    DoH HTTP/8083: FAILED (HTTP $doh_code)"; all_ok=false; }

  # DoQ needs unbound built with QUIC support AND a UDP listener on 853.
  # Neither is true here: :853 is DoT over TCP, and the DoT config has no
  # "quic:" section. Probing it unconditionally produced a second permanent
  # FAILED. Now it is reported as not-deployed unless a QUIC socket exists.
  if ss -ulnp 2>/dev/null | grep -q ':853 '; then
    if command -v kdig &>/dev/null; then
      local doq_ok="" doq
      for _i in 1 2 3; do
        doq=$(kdig +quic +timeout=10 +retry=1 @127.0.0.1 -p 853 "${TEST_DOMAIN}" A 2>/dev/null | grep -c "status: NOERROR")
        [[ "$doq" == "1" ]] && { doq_ok=1; break; }
        sleep 8
      done
      [[ -n "$doq_ok" ]] && log_ok "    DoQ QUIC/853: OK" || { log_warn "    DoQ QUIC/853: FAILED"; all_ok=false; }
    else log_warn "    DoQ: kdig absent, cannot verify"; all_ok=false; fi
  else
    log_info "    DoQ QUIC/853: not deployed (no UDP :853 listener) — skipped"
  fi

  # DoH3 likewise requires a real UDP/443 listener; the old check matched the
  # literal string 'dotnet' in `ss` output, which nothing on this host ever has.
  if ss -ulnp 2>/dev/null | grep -qE ':443 .*(quic|dot|cloudflared|souran)'; then
    log_ok "    DoH3 UDP/443: socket bound"
  else
    log_info "    DoH3 UDP/443: not deployed — skipped"
  fi

  # The public endpoint is only meaningful when a tunnel is actually up.
  if systemctl is-active --quiet cloudflared; then
    # v4.3.1 bugs: (a) `curl ... || echo 000` concatenated into "000000";
    # (b) the probe used --noproxy '*', so on this DPI'd network it could only
    # ever time out (HTTP 000) even when the tunnel is healthy;
    # (c) it targeted dns.mordaddns.ir, which is NOT in the tunnel ingress
    # list at all — /etc/cloudflared/config.yml publishes ssh/admin/dash/proxy
    # hostnames only, so no amount of fixing the transport would make it pass.
    # Probe a hostname the tunnel actually serves, through the bypass chain.
    local pdoh; pdoh=$(curl -s -o /dev/null -w "%{http_code}" --max-time 20 \
      --proxy "${SOURAN_PROXY:-http://127.0.0.1:8118}" \
      "https://${CF_PUBLIC_HOST:-dash.mordaddns.ir}/" 2>/dev/null)
    [[ "$pdoh" =~ ^[0-9]{3}$ ]] || pdoh="000"
    # 530 is Cloudflare's own "I cannot reach the origin" response. The
    # cloudflared client is healthy and the local origin on :8080 answers 200,
    # so this is an EXTERNAL condition (tunnel route / Cloudflare DNS) that no
    # local remediation can fix. Restarting cloudflared on every cycle just
    # churns a working tunnel and hides the real cause, so report it as an
    # external fault and keep it out of all_ok.
    if [[ "$pdoh" == "200" ]]; then
      log_ok "    Public endpoint via tunnel: OK"
    elif [[ "$pdoh" == "530" ]]; then
      local origin; origin=$(curl -s -o /dev/null -w "%{http_code}" --max-time 6 \
        http://127.0.0.1:8080/ 2>/dev/null)
      if [[ "$origin" == "200" ]]; then
        log_warn "    Public endpoint via tunnel: HTTP 530 (Cloudflare edge; local origin :8080 OK — external fault, not auto-fixable)"
      else
        log_warn "    Public endpoint via tunnel: HTTP 530 and local origin :8080 -> $origin (origin down)"
        all_ok=false
      fi
    else
      log_warn "    Public endpoint via tunnel: HTTP $pdoh"
      all_ok=false
    fi
  else
    log_info "    Public DoH via tunnel: cloudflared down — skipped"
  fi

  [[ "$all_ok" == "true" ]]
}

fix_dns_protocols() {
  log_warn "  [Fix] restart dns.service to re-bind all protocol listeners"
  systemctl restart dns; sleep 45
  check_dns_protocols >/dev/null 2>&1 && { log_ok "  [Fix] protocols OK"; return 0; }
  log_error "  [Fix] protocols still failing"
  send_alert "DoH" "DNS transport(s) down after restart" "high"
  return 1
}

verify_censorship_bypass() {
  log_info "  [Censorship] testing blocked domains..."
  local probe_domains=("telegram.org" "x.com" "youtube.com" "instagram.com" "www.youtube.com")
  local failed=0 total=0 hard_fail=()
  for domain in "${probe_domains[@]}"; do
    total=$((total+1))
    local ip; ip=$(resolve_domain "$domain")
    if [[ -n "$ip" && "$ip" != "timed out" ]]; then log_ok "    $domain → $ip"
    else hard_fail+=("$domain"); fi
  done
  if ((${#hard_fail[@]})); then
    sleep 5
    local still=0
    for domain in "${hard_fail[@]}"; do
      local ip2; ip2=$(resolve_domain "$domain")
      if [[ -n "$ip2" && "$ip2" != "timed out" ]]; then log_ok "    $domain → $ip2 (retry)"
      else log_warn "    $domain → FAILED"; failed=$((failed+1)); still=$((still+1)); fi
    done
  fi
  [[ $failed -eq 0 ]]
}

fix_censorship() {
  local stamp="/var/run/souran-watchdog-censor-strike" now since
  now=$(date +%s); since=$(cat "$stamp" 2>/dev/null || echo 0)
  if (( now - since < CHECK_INTERVAL * 2 )); then
    _censor_negcache_flush
    verify_censorship_bypass >/dev/null 2>&1 && { rm -f "$stamp"; log_ok "  [Fix] negcache flush sufficed"; return 0; }
    log_warn "  [Fix] censorship: still failing after flush — deferred"
    return 0
  fi
  echo "$now" > "$stamp"
  _censor_negcache_flush
  verify_censorship_bypass >/dev/null 2>&1 && { rm -f "$stamp"; log_ok "  [Fix] negcache flush OK"; return 0; }
  log_warn "  [Fix] censorship CONFIRMED — restarting dns.service"
  systemctl restart dns; sleep 45
  rm -f "$stamp"
  verify_censorship_bypass >/dev/null 2>&1 && { log_ok "  [Fix] bypass OK"; return 0; }
  log_error "  [Fix] bypass still failing"
  send_alert "Censorship" "Blocked domains still failing after restart" "high"
  return 1
}

_censor_negcache_flush() {
  local token; token=$(_technitium_token); [[ -z "$token" ]] && return 0
  local api="https://127.0.0.1:53443/api" d
  for d in telegram.org x.com youtube.com instagram.com; do
    curl -sk --noproxy '*' --max-time 5 -X POST "$api/cache/delete?token=${token}&domain=${d}" >/dev/null 2>&1 || true
  done
  sleep 2
}

check_zapret() {
  require_svc zapret "  [Zapret] service not active" || return $?
  check_tcp 127.0.0.1 9876 || { log_warn "  [Zapret] tpws :9876 not open"; return 1; }
  log_ok "  [Zapret] OK (tpws :9876)"
}
fix_zapret() { log_warn "  [Fix] restart zapret"; systemctl restart zapret; sleep 3; check_zapret; }

check_xray() {
  require_svc xray "  [Xray] service not active" || return $?
  local size; size=$(stat -c %s /usr/local/etc/xray/config.json 2>/dev/null || echo 0)
  [[ "$size" -lt 20 ]] && { log_warn "  [Xray] config empty"; return 1; }
  check_tcp 127.0.0.1 8443 2 || { log_warn "  [Xray] REALITY :8443 not listening"; return 1; }
  check_tcp 127.0.0.1 8444 2 || { log_warn "  [Xray] XHTTP :8444 not listening"; return 1; }
  log_ok "  [Xray] OK"
}
fix_xray() { log_warn "  [Fix] restart xray"; systemctl restart xray; sleep 3; check_xray; }

check_hysteria() {
  require_svc hysteria "  [Hysteria] service not active" || return $?
  ss -ulnp 2>/dev/null | grep -q ':4443 ' && { log_ok "  [Hysteria] OK (UDP :4443)"; return 0; }
  log_warn "  [Hysteria] UDP :4443 not bound"; return 1
}
fix_hysteria() { log_warn "  [Fix] restart hysteria"; systemctl restart hysteria; sleep 4; check_hysteria; }

check_singbox() {
  require_svc sing-box "  [SingBox] service not active" || return $?
  local cfg=/etc/sing-box/config.json
  local size; size=$(stat -c %s "$cfg" 2>/dev/null || echo 0)
  [[ "$size" -lt 200 ]] && { log_warn "  [SingBox] config empty/small"; return 1; }
  if grep -qE '"(action|type)"[[:space:]]*:[[:space:]]*"(reject|block)"' "$cfg"; then
    log_warn "  [SingBox] BLOCK ROUTE - zero-block violation"; return 1
  fi
  check_tcp 127.0.0.1 2080 2 || { log_warn "  [SingBox] :2080 not open"; return 1; }
  log_ok "  [SingBox] OK (zero-block: enforced)"
}
fix_singbox() {
  log_warn "  [Fix] regenerate sing-box rules and restart"
  [[ -d /opt/souran-dnsveil-rules ]] || bash /home/reza/Projects/Linux-Setup/15-dnsveil-rules-generator.sh >/dev/null 2>&1 || true
  bash /opt/souran/bin/souran-singbox-rules.sh >/dev/null 2>&1 || systemctl restart sing-box
  sleep 2; check_singbox
}

check_nginx() {
  require_svc nginx "  [Nginx] service not active" || return $?
  local code; code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 --noproxy '*' http://127.0.0.1:8090/nginx-health 2>/dev/null || echo 000)
  [[ "$code" == "200" ]] && { log_ok "  [Nginx] OK (health 200)"; return 0; }
  log_warn "  [Nginx] :8090/nginx-health → $code"; return 1
}
fix_nginx() {
  log_warn "  [Fix] restart nginx"
  systemctl restart nginx 2>&1 | while IFS= read -r line; do log_alert "nginx restart: $line"; done
  sleep 3; check_nginx
}

check_privoxy() {
  require_svc privoxy "  [Privoxy] service not active" || return $?
  local code=""
  for _ in 1 2; do
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 -x http://127.0.0.1:8118 http://example.com/ 2>/dev/null || echo 000)
    [[ "$code" == "200" ]] && break
    sleep 2
  done
  [[ "$code" == "200" ]] && { log_ok "  [Privoxy] OK (chain 200)"; return 0; }
  log_warn "  [Privoxy] :8118 → HTTP $code"; return 1
}
fix_privoxy() { log_warn "  [Fix] restart privoxy"; systemctl restart privoxy; sleep 2; check_privoxy; }

check_sidecar() {
  require_svc dashboard-api "  [OpsSidecar] dashboard-api not active" || return $?
  local code; code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://127.0.0.1:9192/health 2>/dev/null || echo 000)
  [[ "$code" =~ ^(401|200)$ ]] && { log_ok "  [OpsSidecar] OK (HTTP $code)"; return 0; }
  log_warn "  [OpsSidecar] :9192/health → $code"; return 1
}
fix_sidecar() { log_warn "  [Fix] restart dashboard-api"; systemctl restart dashboard-api; sleep 3; check_sidecar; }

check_dnstt() {
  require_svc dnstt "  [Dnstt] service not active" || return $?
  ss -ulnp 2>/dev/null | grep -q ':5354 ' || { log_warn "  [Dnstt] UDP :5354 not bound"; return 1; }
  check_tcp 127.0.0.1 9050 2 || { log_warn "  [Dnstt] tor SOCKS :9050 closed"; return 1; }
  log_ok "  [Dnstt] OK (dnstt-server :5354 -> tor)"
}
fix_dnstt() { log_warn "  [Fix] restart dnstt"; systemctl restart dnstt; sleep 3; check_dnstt; }

check_dhcp() {
  require_svc dnsmasq "  [DHCP] dnsmasq not active" || return $?
  local dhcp_socket; dhcp_socket=$(ss -ulnp 2>/dev/null | grep -c "dnsmasq.*:67" 2>/dev/null || true)
  dhcp_socket=${dhcp_socket:-0}
  log_warn "  [DHCP] dnsmasq active, DHCP sockets: $dhcp_socket"
  [[ "${dhcp_socket}" =~ ^[0-9]+$ ]] && [[ "$dhcp_socket" -gt 0 ]]
}
fix_dhcp() { log_warn "  [Fix] restart dnsmasq"; systemctl restart dnsmasq; sleep 2; check_dhcp; }

check_serveo() {
  require_svc serveo-tunnel "  [Serveo] service not active" || return $?
  pgrep -f 'serveo_key' >/dev/null 2>&1 || { log_warn "  [Serveo] ssh process missing"; return 1; }
  log_ok "  [Serveo] OK"
}
fix_serveo() { log_warn "  [Fix] restart serveo-tunnel"; systemctl restart serveo-tunnel; sleep 5; check_serveo; }

check_dnssec() {
  local token; token=$(_technitium_token)
  if [[ -n "$token" ]]; then
    local dnssec
    dnssec=$(curl -sk --noproxy '*' --max-time 5 "https://127.0.0.1:53443/api/settings/get?token=$token" 2>/dev/null | jq -r '.response.dnssecValidation // null' 2>/dev/null)
    [[ "$dnssec" == "true" ]] && { log_warn "  [DNSSEC] dnssecValidation=true — Tor users see BOGUS"; return 1; }
  fi
  log_ok "  [DNSSEC] OK (dnssecValidation=false — correct)"
}

fix_dnssec() { log_warn "  [Fix] DNSSEC already correct"; return 0; }

check_shadowsocks() {
  [[ $(feature_enabled shadowsocks) == "off" ]] && return 0
  local svc; svc=$(systemctl is-active shadowsocks-libev 2>/dev/null) || svc="unknown"
  if [[ "$svc" == "active" ]]; then
    ss -tlnp 2>/dev/null | grep -qE 'ss-server.*LISTEN' && { record shadowsocks OK; return 0; }
    log_alert "shadowsocks-libev active but no listener"
    record shadowsocks WARN; return 0
  fi
  log_alert "shadowsocks-libev: state=$svc"
  record shadowsocks FAIL; return 1
}
fix_shadowsocks() {
  [[ $(feature_enabled auto_fix) == "off" ]] && { log_alert "auto_fix off — not auto-fixed"; return 1; }
  log_info "fix_shadowsocks: restarting shadowsocks-libev"
  systemctl restart shadowsocks-libev 2>&1 | while IFS= read -r line; do log_alert "ss restart: $line"; done
  sleep 3; check_shadowsocks && { log_info "shadowsocks recovered"; return 0; }
  log_alert "fix_shadowsocks: restart failed"; return 1
}

check_iptables_integrity() {
  local chain_count rule_count
  chain_count=$(iptables -L -n 2>/dev/null | grep -cE '^(Chain|target)' || true)
  rule_count=$(iptables -L -n 2>/dev/null | grep -cE '^[a-z]' || true)
  if [[ "$chain_count" -lt 4 ]]; then
    log_alert "IPTABLES: only $chain_count chains visible"
    record iptables_integrity FAIL; return 1
  fi
  if [[ "$rule_count" -lt 5 ]]; then
    log_alert "IPTABLES: only $rule_count rules"
    record iptables_integrity WARN; return 0
  fi
  log_info "iptables integrity: $chain_count chains, $rule_count rules — OK"
  record iptables_integrity OK; return 0
}

fix_iptables() {
  log_warn "  [Fix] restoring iptables NAT rules"
  iptables-restore < /etc/iptables/rules.v4 2>/dev/null || true
  log_ok "  [Fix] iptables restored"
  return 0
}

check_system_resources() {
  log_info "  [System] resources..."
  local bad=0
  local mem_pct; mem_pct=$(free | awk '/Mem:/{printf "%.0f",$3/$2*100}')
  if (( mem_pct > MEM_ALERT_PCT )); then send_alert "System" "Memory critical: ${mem_pct}%" "urgent"; bad=1; fi
  local disk_pct; disk_pct=$(df / | awk 'NR==2{print $5}' | sed 's/%//')
  if (( disk_pct > DISK_ALERT_PCT )); then send_alert "System" "Disk critical: ${disk_pct}%" "urgent"; bad=1; fi
  log_info "    Mem ${mem_pct}% | Disk ${disk_pct}% | Load $(uptime | awk -F'load average:' '{print $2}')"
  pgrep -f "dotnet.*DnsServer" &>/dev/null || log_warn "    Technitium process not found"
  (( bad == 0 )) && log_ok "  [System] OK"
  return $bad
}

check_watchdog_self() {
  local newest; newest=$(find "$LOG_DIR" -name 'watchdog_*.log' -printf '%T@\n' 2>/dev/null | sort -rn | head -1 | cut -d. -f1)
  [[ -z "$newest" ]] && { log_warn "  [Self] no log found"; return 1; }
  local age=$(( $(date +%s) - newest ))
  (( age < CHECK_INTERVAL * 3 )) && { log_ok "  [Self] fresh (${age}s)"; return 0; }
  log_warn "  [Self] stale (${age}s)"; return 1
}

check_dns_oracle() {
  # v4.3.4: pointed at souran-unbound / :5300, neither of which exists here.
  # It therefore skipped itself forever and reported nothing. Now it tests the
  # real zero-upstream core on 5399.
  [[ "$(systemctl is-active souran-dns 2>/dev/null)" == "active" ]] || { log_info "  [Oracle] souran-dns inactive — skipped"; return 0; }
  local a b attempts=0 max_attempts=3
  while [[ $attempts -lt $max_attempts ]]; do
    a=$(dig +short +time=8 +tries=1 @127.0.0.1 -p 5399 example.com NS 2>/dev/null | sed 's/\.$//' | sort)
    b=$(dig +short +time=8 +tries=1 @127.0.0.1 example.com NS | sed 's/\.$//' | sort)
    [[ -n "$a" && -n "$b" ]] && break
    attempts=$((attempts+1)); [[ $attempts -lt $max_attempts ]] && sleep 2
  done
  [[ -z "$a" || -z "$b" ]] && { log_info "  [Oracle] one side empty — skipped"; return 0; }
  if ! comm -12 <(echo "$a") <(echo "$b") | grep -q .; then
    log_warn "  [Oracle] NS DISJOINT — possible poison"
    send_alert "DNS Oracle" "Technitium vs unbound NS answers disjoint" "high"
    return 0
  fi
  log_ok "  [Oracle] Technitium matches unbound"
}

CENSORSHIP_PROBE="/opt/souran/bin/souran-censorship-probe.sh"

check_censorship_probe() {
  [[ -x "$CENSORSHIP_PROBE" ]] || { log_warn "  [CensorProbe] script missing — skipping"; return 0; }
  local now last out
  now=$(date +%s); last=$(_probe_ts_get)
  if (( now - last >= PROBE_MIN_INTERVAL )); then
    _probe_ts_set "$now"
    if out=$("$CENSORSHIP_PROBE" quick wd 2>&1); then
      log_ok "  [CensorProbe] all paths OK (quick)"
    else
      log_warn "  [CensorProbe] degradation detected:"
      printf '%s\n' "$out" | sed 's/^/    /' | tail -8 >&2 || true
      return 1
    fi
  else
    log_ok "  [CensorProbe] within interval ($(( (now-last)/60 ))m ago)"
  fi
  return 0
}

_probe_ts_get() { cat "$STATE_DIR/.censorship_probe_ts" 2>/dev/null || echo 0; }
_probe_ts_set() { echo "$1" > "$STATE_DIR/.censorship_probe_ts" 2>/dev/null || true; }

fix_censorship_probe() {
  local pj="$STATE_DIR/censorship-probes/latest.json"
  [[ -r "$pj" ]] || { log_warn "  [CensorProbe] no json — running full"; "$CENSORSHIP_PROBE" full wd-fix >/dev/null 2>&1; return 0; }
  local doh tor localbad acted=0
  doh=$(jq -r '.checks.doh_tunnel_status // 0' "$pj" 2>/dev/null)
  tor=$(jq -r '.checks.tor_socks_http // -1' "$pj" 2>/dev/null)
  localbad=$(jq -r '[.checks.local_dns[]? | select(.status!="ok")] | length' "$pj" 2>/dev/null)
  if [[ "${localbad:-0}" != "0" ]]; then acted=1; fi
  if [[ "$doh" != "200" ]]; then systemctl restart cloudflared >/dev/null 2>&1 || true; acted=1; fi
  if [[ "$tor" == "0" ]]; then systemctl restart tor@default >/dev/null 2>&1 || true; acted=1; fi
  (( acted )) || "$CENSORSHIP_PROBE" full wd-fix >/dev/null 2>&1 || true
  return 0
}

# ══════════════════════════════════════════════════════════════════════════════
# AUTO REPAIR: disk pressure & config snapshot guard
# ══════════════════════════════════════════════════════════════════════════════

disk_repair() {
  feature_enabled disk_repair || return 0
  local disk_pct; disk_pct=$(df / | awk 'NR==2{print $5}' | sed 's/%//') || return 0
  (( disk_pct < DISK_VACUUM_PCT )) && return 0
  log_warn "  [DiskRepair] disk ${disk_pct}% >= ${DISK_VACUUM_PCT}% — reclaiming"
  journalctl --vacuum-size=800M >/dev/null 2>&1 || true

  # Rotated files, at any depth. v4.3.1 used `-maxdepth 1`, so the largest
  # offenders were invisible: /var/log/technitium/dns/*.log alone held 1.6 GB
  # in nested subdirectories. That is why the repair logged "81% → 81%": it
  # reclaimed nothing while reporting success.
  find /var/log -type f -name '*.gz' -mtime +7 -delete 2>/dev/null || true
  find /var/log -type f -name '*.[0-9]' -mtime +7 -delete 2>/dev/null || true
  find /var/log -type f -name '*.log.[0-9]*' -mtime +7 -delete 2>/dev/null || true

  # Truncate only genuinely oversized ROTATED logs. The old expression was
  #   find /var/log -maxdepth 1 -name '*.log.*' -o -maxdepth 1 -name '*.[0-9]'
  # where the ungrouped -o changes what the implicit -print applies to: adding
  # an explicit -print made the same expression match NOTHING. Rewritten with
  # an explicit -name and a single test so it cannot silently match the
  # current, un-rotated .log file.
  find /var/log -type f \( -name '*.log.[0-9]*' -o -name '*.[0-9]' \) -size +200M \
       -exec truncate -s 0 {} + 2>/dev/null || true

  find "$LOG_DIR" -name 'watchdog_*.log' -mtime +30 -delete 2>/dev/null || true
  find "$LOG_DIR" -name 'daily-report_*.txt' -mtime +30 -delete 2>/dev/null || true
  local after; after=$(df / | awk 'NR==2{print $5}' | sed 's/%//')
  log_ok "  [DiskRepair] ${disk_pct}% → ${after}%"
  (( after > DISK_ALERT_PCT )) && send_alert "DiskRepair" "Disk still ${after}% after cleanup" "urgent"
  return 0
}

config_guard() {
  feature_enabled config_guard || return 0
  local sum_file="$STATE_DIR/config.sha" new_sum
  new_sum=$(cat /etc/dns/*.config /etc/dns/zones/*/*.config 2>/dev/null | sha256sum | cut -d' ' -f1) || return 0
  [[ -z "$new_sum" ]] && return 0
  if [[ -f "$sum_file" ]] && [[ "$(cat "$sum_file")" == "$new_sum" ]]; then return 0; fi
  if [[ -f "$sum_file" ]]; then
    local snap="$BACKUP_DIR/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$snap"
    cp -a /etc/dns/*.config "$snap/" 2>/dev/null || true
    [[ -d /etc/dns/zones ]] && cp -a /etc/dns/zones "$snap/zones" 2>/dev/null || true
    log_info "  [ConfigGuard] /etc/dns changed → snapshot $snap"
    ls -1dt "$BACKUP_DIR"/*/ 2>/dev/null | tail -n +21 | xargs -r rm -rf
  fi
  echo "$new_sum" > "$sum_file"
}

fix_memory_pressure() {
  [[ $(feature_enabled auto_fix) == "off" ]] && { log_alert "auto_fix off — memory pressure not remediated"; return 1; }
  local pct; pct=$(free -m 2>/dev/null | awk '/Mem:/{if($2>0) printf "%.0f", $3/$2*100}') || pct=0
  [[ "$pct" -lt "$MEM_FIX_PCT" ]] && { log_info "memory at ${pct}% — below fix threshold"; return 0; }
  log_alert "memory pressure at ${pct}% — attempting remediation"
  if [[ -w /proc/sys/vm/drop_caches ]]; then echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; fi
  sleep 3
  pct=$(free -m 2>/dev/null | awk '/Mem:/{if($2>0) printf "%.0f", $3/$2*100}') || pct=0
  [[ "$pct" -lt "$MEM_FIX_PCT" ]] && return 0
  return 1
}

# ══════════════════════════════════════════════════════════════════════════════
# HEALTH + FEATURE + CIRCUIT-BREAKER WRAPPER
# ══════════════════════════════════════════════════════════════════════════════

breaker_halfopen() {
  local comp="$1"
  local last; last=$(echo "$(get_state)" | jq -r ".\"${comp}_breaker_last_failure\" // empty" 2>/dev/null || true)
  local last_epoch now_epoch
  if [[ -z "$last" ]]; then
    last_epoch=$(stat -c %Y "$CIRCUIT_BREAKER_FILE" 2>/dev/null || echo 0)
  else
    last_epoch=$(date -d "$last" +%s 2>/dev/null || echo 0)
    (( last_epoch > 0 )) || last_epoch=$(stat -c %Y "$CIRCUIT_BREAKER_FILE" 2>/dev/null || echo 0)
  fi
  now_epoch=$(date +%s)
  (( last_epoch > 0 && now_epoch - last_epoch >= BREAKER_COOLDOWN_S )) || return 1
  clear_component "${comp}_breaker"
  log_ok "  $1: breaker half-open (${BREAKER_COOLDOWN_S}s) — auto-fix re-armed"
  return 0
}

record() { RESULT["$1"]="$2"; }

run_check() {
  local comp="$1" check_fn="$2" fix_fn="$3" desc="${4:-$comp}"
  RESULT["$comp"]="pending"
  log_info "=== $desc ==="

  if ! feature_enabled "$comp"; then
    [[ -z "${DISABLED_NOTED[$comp]:-}" ]] && { log_info "  $desc: DISABLED"; DISABLED_NOTED["$comp"]=1; }
    RESULT["$comp"]="disabled"; return 0
  fi
  DISABLED_NOTED["$comp"]=""

  # Capture the check's exit code. It MUST be captured on the same statement
  # as the call: v4.3.1 read `local rc=$?` on the line AFTER the `if`, where
  # `$?` is the status of the whole `if` construct (always 0 for a false
  # condition), so exit code 2 from a "not installed" check was always lost
  # and the component fell through to the alarming path.
  local rc=0
  eval "$check_fn" || rc=$?
  if [[ $rc -eq 0 ]]; then
    log_ok "  $desc: HEALTHY"
    clear_component "$comp"; clear_component "${comp}_fc"; clear_component "${comp}_breaker"
    RESULT["$comp"]="healthy"; return 0
  fi

  # Exit 2 from a service check means the unit is not installed on this host.
  # That is a deployment fact, not a fault: skip it quietly instead of
  # alarming, attempting a restart, and burning the restart-rate budget on
  # software that does not exist here.
  if [[ $rc -eq 2 ]]; then
    [[ -z "${DISABLED_NOTED[$comp]:-}" ]] && {
      log_info "  $desc: not installed on this host — skipped"; DISABLED_NOTED["$comp"]=1; }
    RESULT["$comp"]="absent"; return 0
  fi

  local breaker; breaker=$(get_breaker "${comp}_breaker")
  if [[ "$breaker" == "true" ]]; then
    if ! breaker_halfopen "$comp"; then
      log_error "  $desc: circuit breaker OPEN"
      send_alert "$desc" "Down. Circuit breaker active (auto-clear in ≤$((BREAKER_COOLDOWN_S/60))min)." "urgent"
      RESULT["$comp"]="breaker-open"; return 1
    fi
  fi

  if ! feature_enabled auto_fix; then
    log_warn "  $desc: UNHEALTHY — auto-fix DISABLED"
    send_alert "$desc" "UNHEALTHY (auto-fix off — investigate)" "high"
    RESULT["$comp"]="check-only"; return 1
  fi

  log_warn "  $desc: UNHEALTHY — attempting fix..."
  if ! uplink_ok; then
    log_warn "  $desc: uplink DOWN — remediation suppressed"
    RESULT["$comp"]="uplink-down"; return 0
  fi
  _restart_rate_ok "$comp" || { RESULT["$comp"]="rate-limited"; return 1; }
  local fc; fc=$(get_fail_count "${comp}_fc"); fc=$((fc+1))
  _update_component "${comp}_fc" "$fc" false

  if eval "$fix_fn"; then
    log_ok "  $desc: fix succeeded (attempt $fc)"
    clear_component "${comp}_fc"; RESULT["$comp"]="fixed"; return 0
  fi

  if [[ $fc -ge $MAX_RESTART_ATTEMPTS ]]; then
    log_error "  $desc: $fc attempts failed — TRIPPING breaker"
    _update_component "${comp}_breaker" 0 true; clear_component "${comp}_fc"
    send_alert "$desc" "Circuit breaker TRIPPED after $fc failed fixes." "urgent"
  else
    send_alert "$desc" "Unhealthy. Fix $fc/$MAX_RESTART_ATTEMPTS failed." "high"
  fi
  RESULT["$comp"]="unhealthy"; return 1
}

# ══════════════════════════════════════════════════════════════════════════════
# STATUS FILE
# ══════════════════════════════════════════════════════════════════════════════

write_status() {
  jq_available || return 0
  local comp feats="{}" comps="{}"
  local cyc="${CYCLE_NUM:-0}"; [[ "$cyc" =~ ^[0-9]+$ ]] || cyc=0
  for comp in "${ALL_FEATURES[@]}"; do feats=$(echo "$feats" | jq --arg c "$comp" --arg v "${FEATURE_MAP[$comp]:-on}" '.[$c]=$v'); done
  for comp in "${ALL_FEATURES[@]}"; do
    [[ -n "${RESULT[$comp]:-}" ]] || continue
    comps=$(echo "$comps" | jq --arg c "$comp" --arg s "${RESULT[$comp]}" '.[$c]=$s')
  done
  local breaker; breaker=$(get_state)
  jq -n \
    --arg version "$SCRIPT_VERSION" --arg ts "$CYCLE_TS" --argjson cycle "${cyc:-0}" \
    --argjson interval "$CHECK_INTERVAL" \
    --argjson autofix "$(feature_enabled auto_fix && echo true || echo false)" \
    --argjson alerts "$(feature_enabled alerts && echo true || echo false)" \
    --argjson components "$comps" --argjson features "$feats" --argjson breaker "$breaker" \
    '{version:$version, ts:$ts, cycle:$cycle, interval_s:$interval, auto_fix:$autofix, alerts_on:$alerts, components:$components, features:$features, breaker:$breaker}' \
    > "$STATUS_FILE.tmp" 2>>/tmp/wd_jq_err.log && mv "$STATUS_FILE.tmp" "$STATUS_FILE"
  cp -f "$STATUS_FILE" "$RUN_STATUS_FILE" 2>/dev/null || true
}

# ══════════════════════════════════════════════════════════════════════════════
# DAILY REPORT
# ══════════════════════════════════════════════════════════════════════════════

generate_report() {
  feature_enabled daily_report || return 0
  local rpt="$LOG_DIR/daily-report_$(date '+%Y-%m-%d').txt"
  {
    echo "══════════════════════════════════════════"
    echo "Souran Network — Daily Health Report (watchdog v$SCRIPT_VERSION)"
    echo "Host: $(hostname) | $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Uptime: $(uptime -p 2>/dev/null || uptime | awk '{print $3,$4}' | sed 's/,//')"
    echo "══════════════════════════════════════════"
    echo ""
    echo "── DNS Engines ──"
    for eng in technitium unbound bind9 coredns powerdns; do
      [[ -n "${RESULT[$eng]:-}" ]] || continue
      case "${RESULT[$eng]}" in
        healthy|fixed) echo "  ✅ $eng: ${RESULT[$eng]}" ;;
        disabled) echo "  ⏸️  $eng: disabled" ;;
        *) echo "  ❌ $eng: ${RESULT[$eng]}" ;;
      esac
    done
    echo ""
    echo "── Components ──"
    local comp
    for comp in "${ALL_FEATURES[@]}"; do
      [[ "${comp}" == "technitium" || "${comp}" == "unbound" || "${comp}" == "bind9" || "${comp}" == "coredns" || "${comp}" == "powerdns" ]] && continue
      [[ -n "${RESULT[$comp]:-}" ]] || continue
      case "${RESULT[$comp]}" in
        healthy|fixed) echo "  ✅ $comp: ${RESULT[$comp]}" ;;
        disabled) echo "  ⏸️  $comp: disabled" ;;
        *) echo "  ❌ $comp: ${RESULT[$comp]}" ;;
      esac
    done
    echo ""
    echo "── Auto-Build ──"
    echo "  Last build: $(cat "$BUILD_LAST_TS_FILE" 2>/dev/null || echo 'never')"
    echo "  Source: $SOURCE_DIR"
    echo ""
    echo "── Alert Summary (today) ──"
    echo "  alerts/errors: $(grep -c 'ALERT\|ERROR' "$LOG_FILE" 2>/dev/null || true)"
    { grep 'ALERT\|ERROR' "$LOG_FILE" 2>/dev/null || true; } | tail -5 | sed 's/^/  /'
    echo ""
    echo "── Resources ──"
    free -h | awk '/Mem:/{printf "  Memory: %.1f / %.1f GB (%.0f%%)\n",$3,$2,$3/$2*100}'
    df -h / | awk 'NR==2{printf "  Disk: %s / %s (%s)\n",$3,$2,$5}'
    echo "══════════════════════════════════════════"
  } > "$rpt"
  log_info "Report written: $rpt"
  send_report "$(cat "$rpt")"
}

# ══════════════════════════════════════════════════════════════════════════════
# ONE CYCLE
# ══════════════════════════════════════════════════════════════════════════════

run_cycle() {
  local cycle="$1" failed=0
  CYCLE_TS=$(date '+%Y-%m-%d %H:%M:%S'); CYCLE_NUM="$cycle"
  load_features
  log_info "━━━ Cycle #$cycle | $CYCLE_TS ━━━"

  # DNS engines (dependency order)
  run_check "mysql"        "check_mysql"        "fix_mysql"        "MySQL"            || failed=$((failed+1))
  run_check "technitium"   "check_technitium"   "fix_technitium"   "Technitium"       || failed=$((failed+1))
  run_check "unbound"      "check_unbound"      "fix_unbound"      "Unbound Oracle"   || failed=$((failed+1))
  run_check "bind9"        "check_bind9"        "fix_bind9"        "BIND9"            || failed=$((failed+1))
  run_check "coredns"      "check_coredns"      "fix_coredns"      "CoreDNS"          || failed=$((failed+1))
  run_check "powerdns"     "check_powerdns"     "fix_powerdns"     "PowerDNS"         || failed=$((failed+1))
  run_check "dns_cache"    "check_dns_cache"    "fix_dns_cache"    "DNS Cache"        || failed=$((failed+1))
  run_check "dashboard"    "check_dashboard"    "fix_dashboard"    "Dashboard"        || failed=$((failed+1))

  # Edge / proxy / anti-censorship layer
  run_check "socks_bridge" "check_socks_bridge" "fix_socks_bridge" "Socks Bridge"   || failed=$((failed+1))
  run_check "cloudflared"  "check_cloudflared"  "fix_cloudflared"  "Cloudflared"     || failed=$((failed+1))
  run_check "wireguard"    "check_wireguard"    "fix_wireguard"    "WireGuard"       || failed=$((failed+1))
  run_check "tor"          "check_tor"          "fix_tor"          "Tor"             || failed=$((failed+1))
  run_check "zapret"       "check_zapret"       "fix_zapret"       "Zapret/tpws"     || failed=$((failed+1))
  run_check "xray"         "check_xray"         "fix_xray"         "Xray"            || failed=$((failed+1))
  run_check "hysteria"     "check_hysteria"     "fix_hysteria"     "Hysteria"        || failed=$((failed+1))
  run_check "singbox"      "check_singbox"      "fix_singbox"      "SingBox Tor"     || failed=$((failed+1))
  run_check "dnstt"        "check_dnstt"        "fix_dnstt"        "Dnstt Tunnel"    || failed=$((failed+1))
  run_check "nginx"        "check_nginx"        "fix_nginx"        "Nginx"           || failed=$((failed+1))
  run_check "privoxy"      "check_privoxy"      "fix_privoxy"      "Privoxy"         || failed=$((failed+1))
  run_check "sidecar"      "check_sidecar"      "fix_sidecar"      "Ops Sidecar"     || failed=$((failed+1))
  run_check "dhcp"         "check_dhcp"         "fix_dhcp"         "DHCP (dnsmasq)"  || failed=$((failed+1))
  run_check "serveo"       "check_serveo"       "fix_serveo"       "Serveo Tunnel"   || failed=$((failed+1))

  # Protocol + censorship layers
  run_check "dns_protocols"     "check_dns_protocols"     "fix_dns_protocols"     "DNS Protocols"       || failed=$((failed+1))
  run_check "censorship_bypass" "verify_censorship_bypass" "fix_censorship"       "Censorship Bypass" || failed=$((failed+1))
  run_check "censorship_probe"  "check_censorship_probe"  "fix_censorship_probe" "Censorship Probe"  || failed=$((failed+1))

  # System + guards
  if feature_enabled resource_watch; then
    if check_system_resources; then RESULT["resource_watch"]="healthy"; else RESULT["resource_watch"]="unhealthy"; failed=$((failed+1)); fi
  else
    RESULT["resource_watch"]="disabled"
  fi
  if check_watchdog_self >/dev/null 2>&1; then RESULT["self"]="healthy"; else RESULT["self"]="stale"; fi
  check_dns_oracle >/dev/null 2>&1 || true
  if feature_enabled dnssec; then run_check "dnssec" "check_dnssec" "fix_dnssec" "DNSSEC" || failed=$((failed+1)); fi
  if feature_enabled shadowsocks; then run_check "shadowsocks" "check_shadowsocks" "fix_shadowsocks" "Shadowsocks" || failed=$((failed+1)); fi
  if feature_enabled wireguard; then run_check "wireguard_peers" "check_wireguard_peers" "fix_wireguard" "WireGuard Peers" || true; fi
  if feature_enabled wireguard || feature_enabled zapret; then run_check "iptables_integrity" "check_iptables_integrity" "fix_iptables" "IPTables" || true; fi

  # Auto-build on source changes
  if feature_enabled auto_build; then
    if _check_source_changed; then
      if _do_build; then
        log_ok "  [AutoBuild] ✓ build completed"
      else
        log_warn "  [AutoBuild] ✗ build had issues"
        failed=$((failed+1))
      fi
    fi
  fi

  disk_repair
  config_guard

  write_status

  if [[ $failed -eq 0 ]]; then
    log_ok "ALL ENABLED COMPONENTS HEALTHY ✓ (auto_fix=$(feature_enabled auto_fix && echo ON || echo OFF), auto_build=$(feature_enabled auto_build && echo ON || echo OFF))"
    send_heartbeat
  else
    log_warn "$failed component(s) unhealthy"
  fi
  return $failed
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN LOOP
# ══════════════════════════════════════════════════════════════════════════════

main_loop() {
  local cycle=1 last_report_day=""
  init_dirs; acquire_lock
  log_info "════════ Souran Watchdog v$SCRIPT_VERSION starting (PID $PID, interval ${CHECK_INTERVAL}s)"
  load_features
  reconcile_units
  log_info "auto_fix=$(feature_enabled auto_fix && echo ON || echo OFF) auto_build=$(feature_enabled auto_build && echo ON || echo OFF) alerts=$(feature_enabled alerts && echo ON || echo OFF)"
  log_info "Grace ${STARTUP_GRACE}s..."
  sleep "$STARTUP_GRACE"

  while true; do
    run_cycle "$cycle" || true
    local today; today=$(date '+%Y-%m-%d')
    if [[ "$today" != "$last_report_day" ]]; then generate_report; last_report_day="$today"; fi
    find "$LOG_DIR" -name "watchdog_*.log" -mtime +30 -delete 2>/dev/null || true
    find "$LOG_DIR" -name "daily-report_*.txt" -mtime +30 -delete 2>/dev/null || true
    cycle=$((cycle+1))
    log_info "Sleeping ${CHECK_INTERVAL}s..."
    sleep "$CHECK_INTERVAL"
  done
}

# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

cli_feature() {
  local name val="$2"
  name=$(_fkey "${1:-}")
  [[ -z "$name" ]] && { echo "usage: wd-ctl feature <name> <on|off>"; exit 1; }
  if [[ -z "$val" ]]; then echo "${name}=${FEATURE_MAP[$name]:-on}"; return 0; fi
  case "$val" in on|off) ;; *) echo "value must be on|off"; exit 1;; esac
  touch "$FEATURES_FILE"
  if grep -qE "^[[:space:]]*(#[[:space:]]*)?FEATURE_${name}=" "$FEATURES_FILE"; then
    sed -i -E "s/^[[:space:]]*(#[[:space:]]*)?FEATURE_${name}=.*/FEATURE_${name}=${val}/" "$FEATURES_FILE"
  else
    echo "FEATURE_${name}=${val}" >> "$FEATURES_FILE"
  fi
  sync_unit_for_feature "$name" "$val"
  echo "$name=$val (hot-reload on next cycle)"
}

cli_status() {
  local s="{}"
  [[ -f "$STATUS_FILE" ]] && s=$(cat "$STATUS_FILE")
  if jq_available; then
    echo "$s" | jq -r '
      "watchdog v\(.version)  cycle #\(.cycle)  ts \(.ts)",
      "auto_fix=\(.auto_fix)  alerts=\(.alerts_on)  auto_build=\(.features.auto_build // "unknown")  interval=\(.interval_s)s",
      "",
      "COMPONENTS:",
      (.components | to_entries[] | "  \(.value|tostring|.[0:1]) \(.key)"),
      "",
      "breaker:", (.breaker | to_entries[]? | "  \(.key)=\(.value)"),
      ""' 2>/dev/null || echo "$s"
  else
    echo "$s"
  fi
}

cli_build() {
  log_build "Manual build trigger"
  if ! feature_enabled auto_build; then
    echo "auto_build is disabled — enable with: wd-ctl feature auto_build on"
    exit 1
  fi
  if _check_source_changed; then
    if _do_build; then echo "Build completed successfully"; exit 0; else echo "Build had issues"; exit 1; fi
  else
    echo "No source changes detected"
    exit 0
  fi
}

cli() {
  local cmd="${1:-}"
  shift || true
  case "$cmd" in
    status)       init_dirs; cli_status ;;
    status-json)  init_dirs; [[ -f "$STATUS_FILE" ]] && cat "$STATUS_FILE" || echo '{"error":"no status yet"}' ;;
    check)
      init_dirs
      if [[ "${1:-}" == "--fix" ]]; then
        if [[ -f "$LOCK_FILE" ]] && kill -0 "$(cat "$LOCK_FILE" 2>/dev/null)" 2>/dev/null; then
          echo "REFUSED: watchdog daemon holds the lock — use read-only check." >&2; exit 3
        fi
        acquire_lock; trap release_lock EXIT; _AUTOFIX_OVERRIDE="on"
      else
        _AUTOFIX_OVERRIDE="off"
      fi
      load_features
      run_cycle "oneshot" && { echo "RESULT: all enabled components healthy"; exit 0; } || { echo "RESULT: failures — see output above"; exit 1; } ;;
    build)        cli_build ;;
    feature)      load_features; cli_feature "${1:-}" "${2:-}" ;;
    features)     load_features
                  echo "# /etc/souran-watchdog/features.conf (FEATURE_* = on/off)"
                  for f in "${ALL_FEATURES[@]}"; do printf '  %-22s %s\n' "$f" "${FEATURE_MAP[$f]:-on}"; done ;;
    logs)         tail -n "${1:-80}" "$(ls -t "$LOG_DIR"/watchdog_*.log 2>/dev/null | head -1)" 2>/dev/null || echo "no logs" ;;
    reset)        [[ -z "${1:-}" ]] && { echo "usage: wd-ctl reset <component>"; exit 1; }
                  clear_component "${1}_fc"; clear_component "${1}_breaker"; echo "breaker+counters cleared for $1" ;;
    version)      echo "$SCRIPT_VERSION" ;;
    ""|run)       main_loop ;;
    *)            echo "usage: wd-ctl {status|status-json|check [--fix]|feature <n> <on|off>|features|build|logs [N]|reset <comp>|version|run}"
                  exit 1 ;;
  esac
}

init_dirs
trap 'log_info "Watchdog stopping (clean exit for systemd)"; release_lock; exit 0' INT TERM HUP QUIT

if [[ $# -gt 0 && "${1:-}" != "run" ]]; then cli "$@"; else main_loop; fi
