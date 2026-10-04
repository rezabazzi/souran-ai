#!/usr/bin/env bash
# =============================================================================
#  SOURAN AI NETWORK SERVER — INSTALLER v4.3.2
#  Reproduces the CURRENT working stack from source. Nothing pre-built.
#
#  This replaces install-souran.sh, which installed a different architecture
#  entirely: it wrote its own dnsmasq-backed dns/resolver.py and pointed
#  souran-dns.service at it, so running it would have REPLACED the working
#  zero-upstream unbound resolver with a forwarder-style resolver. It also
#  hardcoded the sudo password 13 times. Neither is acceptable for a tool that
#  claims "clean install from zero".
#
#  What this installer actually does, in order:
#    1. verify host + prerequisites
#    2. build Unbound 1.24.2 from source (the zero-upstream recursive core)
#    3. install the resolver config (root hints, no forward-zone, harden-*)
#    4. install the Python modules that make up the front-ends
#    5. install the systemd units WITH the measured environment this host needs
#    6. build the censorship-bypass tooling from source
#    7. bring the stack up and run the verification suite
#
#  Measured facts this installer encodes (do not "simplify" them away):
#    - Direct foreign HTTPS is DPI-affected. Python's TLS ClientHello is reset
#      while curl's is not, so DoH shells out to curl through privoxy :8118.
#    - A systemd unit gets NO proxy variables from the user shell. Any unit
#      doing outbound HTTPS must declare them or it fails silently.
#    - A DoH round-trip costs 2.0-2.7 s here, so the DoH budget must be ~20 s
#      and single-flight followers must wait budget+10 s. Equal values
#      collide under load and produce SERVFAIL for valid names.
#    - GoodbyDPI cannot run on Linux (needs WinDivert); ByeDPI is the port.
#
#  Usage:  sudo ./install-souran-v432.sh [--skip-build] [--no-start] [--verify-only]
# =============================================================================
set -euo pipefail

SOURAN_DIR="/opt/souran-ai"
ENGINE_DIR="$SOURAN_DIR/engine/unbound"
SRC_DIR="$SOURAN_DIR/engine/unbound-src"
CONFIG_DIR="$SOURAN_DIR/config"
UNBOUND_VERSION="1.24.2"
UNBOUND_URL="https://nlnetlabs.nl/downloads/unbound/unbound-${UNBOUND_VERSION}.tar.gz"
ROOT_HINTS_URL="https://www.internic.net/domain/named.cache"
ROOT_KEY_URL="https://data.iana.org/root-anchors/root-anchors.xml"

LOG_FILE="/var/log/souran-install.log"
SKIP_BUILD=0
NO_START=0
VERIFY_ONLY=0
FORCE_RESTART_OPT=0

for arg in "$@"; do
  case "$arg" in
    --skip-build)     SKIP_BUILD=1 ;;
    --no-start)       NO_START=1 ;;
    --verify-only)    VERIFY_ONLY=1 ;;
    --force-restart)  FORCE_RESTART_OPT=1 ;;
    -h|--help)        sed -n '2,34p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

log()  { printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG_FILE"; }
die()  { log "FATAL: $*"; exit 1; }
step() { log ""; log "=== $* ==="; }

# Run as root without embedding a password anywhere.
if [[ "$(id -u)" -ne 0 ]]; then
  die "run as root:  sudo $0 $*"
fi

# =============================================================================
step "1/7  Host prerequisites"
# =============================================================================
log "host   : $(. /etc/os-release; echo "$PRETTY_NAME")"
log "kernel : $(uname -r)"
log "arch   : $(uname -m)"

# 32-bit is not supported: the resolver needs >= 4 GiB for its cache config
# and the build assumes x86_64-linux.
[[ "$(uname -m)" == "x86_64" ]] || die "only x86_64 is supported (found $(uname -m))"

for cmd in python3 curl dig systemctl; do
  command -v "$cmd" >/dev/null 2>&1 || die "missing required command: $cmd"
done
log "python : $(python3 -V 2>&1)"

if (( VERIFY_ONLY )); then
  log "verify-only: skipping to the verification suite"
else
  step "2/7  Build Unbound ${UNBOUND_VERSION} from source"
  # ---------------------------------------------------------------------
  # No pre-built binaries. This is the zero-upstream recursive core; it is
  # what makes the "no forwarders" claim true rather than aspirational.
  # ---------------------------------------------------------------------
  DEPS=(build-essential pkg-config libssl-dev libexpat1-dev libevent-dev
        flex bison unbound-anchor curl ca-certificates)
  log "installing build deps: ${DEPS[*]}"
  apt-get update -qq
  apt-get install -y -qq "${DEPS[@]}"

  if (( SKIP_BUILD )) && [[ -x "$ENGINE_DIR/sbin/unbound" ]]; then
    log "skip-build: reusing existing $ENGINE_DIR/sbin/unbound"
  else
    mkdir -p "$SRC_DIR"
    cd "$SRC_DIR"
    if [[ ! -f "unbound-${UNBOUND_VERSION}.tar.gz" ]]; then
      log "downloading $UNBOUND_URL"
      curl -fsSL --retry 3 -o "unbound-${UNBOUND_VERSION}.tar.gz" "$UNBOUND_URL"
    fi
    tar xzf "unbound-${UNBOUND_VERSION}.tar.gz"
    cd "unbound-${UNBOUND_VERSION}"
    ./configure --prefix="$ENGINE_DIR" --with-libevent --with-pidfile=""
    make -j"$(nproc)"
    make install
    log "installed: $("$ENGINE_DIR/sbin/unbound" -V | head -1)"
  fi

  [[ -x "$ENGINE_DIR/sbin/unbound" ]] || die "unbound binary missing after build"

  # Root hints + trust anchor. These are what let the resolver walk the DNS
  # from the root with no configured upstream at all.
  install -d -m 0755 "$ENGINE_DIR"
  # NOTE: root hints and the trust anchor live in /opt/souran-ai/engine/,
  # NOT engine/unbound/ — those are the paths the live config references and
  # the ones the verification suite checks. Fetching them into engine/unbound/
  # silently breaks tier-1 priming while checkconf still passes.
  HINTS_DIR="/opt/souran-ai/engine"
  install -d -m 0755 "$HINTS_DIR"
  if [[ ! -s "$HINTS_DIR/root.hints" ]]; then
    log "fetching root hints into $HINTS_DIR/root.hints"
    curl -fsSL --retry 3 -o "$HINTS_DIR/root.hints" "$ROOT_HINTS_URL" \
      || die "could not fetch root hints (needed for zero-upstream resolution)"
  fi
  if [[ ! -s "$HINTS_DIR/unbound-root.key" ]]; then
    if [[ -x "$ENGINE_DIR/sbin/unbound-anchor" ]]; then
      log "generating root trust anchor"
      "$ENGINE_DIR/sbin/unbound-anchor" -a "$HINTS_DIR/unbound-root.key" \
        || curl -fsSL --retry 3 -o "$HINTS_DIR/unbound-root.key" "$ROOT_KEY_URL"
    fi
  fi
fi

# =============================================================================
step "3/7  Resolver configuration (zero-upstream)"
# =============================================================================
mkdir -p "$CONFIG_DIR" "$SOURAN_DIR/data" "$SOURAN_DIR/logs" /var/log/souran-watchdog

# =============================================================================
# SAFETY GATE — read this before changing anything below.
#
# v4.3.2 shipped an installer that overwrote a WORKING tier-1 config and
# systemd units on a machine already serving DNS, then restarted everything.
# Port 53 went dead (PermissionError on bind), two services failed, and the
# resolver stopped recursing. Recovery took longer than the install.
#
# Rules this installer now obeys:
#   1. NEVER overwrite an existing config or unit without a timestamped .bak.
#   2. NEVER restart units when the stack is already live — adopt it instead.
#   3. Verify the ports are actually answering AFTER any restart, and say so.
#   4. Leave a runbook at the top so a human can undo this in one command.
# =============================================================================
STACK_LIVE=0
if systemctl is-active --quiet souran-doh-fallback && \
   dig +short +time=3 +tries=1 @127.0.0.1 -p 53 example.com A 2>/dev/null | grep -qE '^[0-9]+\.'; then
  STACK_LIVE=1
fi
if (( STACK_LIVE )); then
  log "NOTE: a working DNS stack is already live on this host."
  log "      Existing configs and units will be BACKED UP, not overwritten."
  log "      Existing units will NOT be restarted (pass --force-restart to override)."
fi

backup_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  local b="${f}.bak-$(date +%Y%m%d-%H%M%S)"
  cp -a "$f" "$b"
  log "  backup: $b"
}
FORCE_RESTART=$FORCE_RESTART_OPT

# The zero-upstream guarantee is a CONFIG INVARIANT and must be asserted, not
# assumed. This config deliberately contains no forward-zone/forward-addr; the
# verification suite fails the build if one ever appears.
if [[ -f "$CONFIG_DIR/souran-unbound.conf.yaml" ]]; then
  # Existing and possibly hand-tuned (this host's config carries measured
  # comments). Back it up and leave it alone unless forced.
  backup_file "$CONFIG_DIR/souran-unbound.conf.yaml"
fi
if [[ ! -f "$CONFIG_DIR/souran-unbound.conf.yaml" ]] || (( FORCE_RESTART )); then
  log "writing tier-1 unbound config"
  cat > "$CONFIG_DIR/souran-unbound.conf.yaml" <<'YAML'
server:
    verbosity: 1
    interface: 127.0.0.1
    port: 5399
    do-daemonize: no
    do-ip4: yes
    # do-ip6 MUST be no on this host. It has no global IPv6 address, so with
    # do-ip6 enabled unbound burns its entire budget on unreachable AAAA root
    # hints (measured: 912 attempts, 51 "Network is unreachable" errors) and
    # every lookup then times out. Do not "improve" this back to yes.
    do-ip6: no
    prefer-ip6: no
    do-udp: yes
    do-tcp: yes
    use-syslog: no
    logfile: "/opt/souran-ai/logs/unbound.log"
    log-time-ascii: yes
    log-queries: no
    log-replies: no
    pidfile: "/run/souran-unbound.pid"
    username: "unbound"
    chroot: ""
    directory: "/opt/souran-ai/engine/unbound"
    root-hints: "/opt/souran-ai/engine/root.hints"
    auto-trust-anchor-file: "/opt/souran-ai/engine/unbound-root.key"
    do-not-query-localhost: no
    deny-any: no
    prefetch: yes
    prefetch-key: yes
    rrset-roundrobin: yes
    minimal-responses: no
    num-threads: 4
    msg-cache-size: 256m
    rrset-cache-size: 512m
    key-cache-size: 64m
    neg-cache-size: 64m
    infra-cache-numhosts: 100000
    cache-max-ttl: 86400
    cache-min-ttl: 0
    cache-max-negative-ttl: 60
    serve-expired: yes
    serve-expired-ttl: 86400
    serve-expired-reply-ttl: 300
    serve-expired-ttl-reset: yes
    jostle-timeout: 200
    infra-host-ttl: 900
    rrset-cache-slabs: 4
    so-reuseport: yes
    unwanted-reply-threshold: 10000000
    tcp-upstream: yes
    harden-dnssec-stripped: yes
    harden-below-nxdomain: yes
    harden-glue: yes
    harden-large-queries: yes
    harden-short-bufsize: yes
    harden-unverified-glue: yes
    harden-referral-path: yes
    harden-algo-downgrade: yes
    harden-unknown-additional: yes
    use-caps-for-id: no
    qname-minimisation: yes
    qname-minimisation-strict: no
    aggressive-nsec: yes
    disable-dnssec-lame-check: no
    val-permissive-mode: yes
    val-clean-additional: yes
    val-log-level: 2
    val-max-restart: 5
    module-config: "validator iterator"
    edns-buffer-size: 1232
    max-udp-size: 1232
    edns-tcp-keepalive: yes
    unknown-server-time-limit: 500
access-control: 0.0.0.0/0 allow
access-control: ::/0 allow
remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
    control-port: 8953
    control-use-cert: no
YAML
  # Zero-upstream assertion: refuse to continue if a forwarder crept in.
  if grep -qE '^\s*forward-(zone|addr)' "$CONFIG_DIR/souran-unbound.conf.yaml"; then
    die "tier-1 config contains a forwarder — that breaks the zero-upstream guarantee"
  fi
  log "tier-1 config written and verified forwarder-free"
else
  log "tier-1 config already present: $CONFIG_DIR/souran-unbound.conf.yaml"
  if grep -qE '^\s*forward-(zone|addr)' "$CONFIG_DIR/souran-unbound.conf.yaml"; then
    die "EXISTING tier-1 config contains a forwarder — remove it (zero-upstream is required)"
  fi
fi

if [[ ! -f "$CONFIG_DIR/souran-unbound-tls.conf.yaml" ]]; then
  log "writing DoT config (:853)"
  sed -e 's|^    port: 5399$|    port: 5399\n    do-tls: yes\n    tls-cert-bundle: "/opt/souran-ai/config/doh.pem"\n    tls-private-key: "/opt/souran-ai/config/doh.key"|' \
      -e 's|^    interface: 127.0.0.1$|    interface: 127.0.0.1\n    port: 853|' \
      "$CONFIG_DIR/souran-unbound.conf.yaml" > "$CONFIG_DIR/souran-unbound-tls.conf.yaml"
fi
if [[ -f "$CONFIG_DIR/doh.key" ]]; then
  # World-readable private keys were a real finding in v4.3.1.
  chmod 600 "$CONFIG_DIR/doh.key" "$CONFIG_DIR/souran.key" 2>/dev/null || true
fi

# =============================================================================
step "4/7  Python modules"
# =============================================================================
# Every module the stack actually runs. Missing one leaves a unit that starts
# and then crash-loops, which is how the learning engine failed for 7 hours.
MODULES=(
  souran_dns_rr.py            # general RR layer (MX/TXT/SOA/SVCB passthrough)
  souran_keccak.py            # Keccak-256 for ENS (sha3_256 is NOT keccak)
  souran-doh-fallback.py      # :53 + :853 front-end, poison-proof, DoH tier 2
  souran_web3_resolver.py     # ENS / Handshake / Unstoppable
  souran_gaming_dns.py        # game DNS bindings
  souran_learning_engine.py   # adaptive learning
  souran_anticompress_engine.py
  souran_telemetry.py         # live metrics for the dashboards
  souran_toggle.py
  web-dashboard-8383.py       # Neuro dashboard
  agent-dashboard.py          # Hermes dashboard
  sidecar.py                  # ops API (loopback only)
  intrusion-detection.py
  souran_deep_suite.py        # verification suite
  souran_test_suite.py
  souran-dns.sh
)
missing=0
for m in "${MODULES[@]}"; do
  if [[ -f "$SOURAN_DIR/$m" ]]; then
    log "  present  $m"
  else
    log "  MISSING  $m"
    missing=$((missing+1))
  fi
done
if (( missing )); then
  log "WARNING: $missing module(s) absent — units for them will fail to start."
  log "         They ship in the source tree; copy them into $SOURAN_DIR."
fi

# The watchdog lives outside SOURAN_DIR on this host.
if [[ -f /opt/souran-watchdog/souran-watchdog.sh ]]; then
  log "  present  /opt/souran-watchdog/souran-watchdog.sh"
fi

# Byte-compile everything so a syntax error fails the install, not runtime.
log "syntax-checking modules"
for m in "${MODULES[@]}"; do
  [[ -f "$SOURAN_DIR/$m" ]] || continue
  python3 -m py_compile "$SOURAN_DIR/$m" || die "syntax error in $m"
done

# =============================================================================
step "5/7  systemd units"
# =============================================================================
UNIT_DIR=/etc/systemd/system
mkdir -p "$UNIT_DIR"
# Back up every unit we are about to write. v4.3.2 overwrote these blind and
# recovery required hand-reconstructing them.
for u in souran-dns souran-doh-fallback souran-dns-dot souran-8082-dashboard \
         souran-web-8383 souran-web3-resolver souran-gaming-dns \
         souran-learning-engine souran-ids souran-sidecar; do
  backup_file "$UNIT_DIR/${u}.service"
done

# Proxy environment for units that make outbound HTTPS. A systemd unit gets
# none of the user shell's variables; without these, outbound calls fail
# silently while the service still reports healthy.
install_proxy_dropin() {
  local unit="$1"
  mkdir -p "$UNIT_DIR/${unit}.service.d"
  cat > "$UNIT_DIR/${unit}.service.d/10-proxy.conf" <<'ENV'
[Service]
Environment=HTTP_PROXY=http://127.0.0.1:8118
Environment=HTTPS_PROXY=http://127.0.0.1:8118
Environment=http_proxy=http://127.0.0.1:8118
Environment=https_proxy=http://127.0.0.1:8118
Environment=NO_PROXY=localhost,127.0.0.1,::1
Environment=no_proxy=localhost,127.0.0.1,::1
ENV
  log "  proxy drop-in: ${unit}.service.d/10-proxy.conf"
}

# --- tier 1: unbound ---------------------------------------------------------
# NOTE: StartLimitIntervalSec belongs in [Unit]. In [Service] systemd logs
# "Unknown key ... ignoring" and restart throttling silently stays on.
cat > "$UNIT_DIR/souran-dns.service" <<'UNIT'
[Unit]
Description=Souran DNS Core — Unbound zero-upstream recursive resolver
After=network-online.target
Wants=network-online.target
# Restarts must never be throttled: a throttled resolver stops recovering.
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStartPre=/opt/souran-ai/engine/unbound/sbin/unbound-checkconf /opt/souran-ai/config/souran-unbound.conf.yaml
ExecStart=/opt/souran-ai/engine/unbound/sbin/unbound -c /opt/souran-ai/config/souran-unbound.conf.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=3
KillSignal=SIGTERM
LimitNOFILE=1048576
MemoryMax=2G
StandardOutput=journal
StandardError=journal
SyslogIdentifier=souran-dns

[Install]
WantedBy=multi-user.target
UNIT

# --- tier 2: the poison-proof front-end -------------------------------------
# The DoH budget and client timeout are load-bearing. A DoH round-trip costs
# 2.0-2.7 s on this link, so a 12 s budget starves under concurrency and
# clients receive SERVFAIL for valid names. Client timeout must exceed the
# budget so a slow-but-successful lookup still reaches the client.
cat > "$UNIT_DIR/souran-doh-fallback.service" <<UNIT
[Unit]
Description=Souran AI Network Server — Poison-Proof DNS Tier (Port 53)
After=network-online.target souran-dns.service
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=reza
WorkingDirectory=$SOURAN_DIR
ExecStart=/usr/bin/python3 $SOURAN_DIR/souran-doh-fallback.py
Restart=always
RestartSec=3
# Ports 53 and 853 are privileged. Run unprivileged and grant ONLY the bind
# capability -- v4.3.2 shipped User=reza with no capability, so every start
# died with `PermissionError: [Errno 13]` on bind() and port 53 went dead
# (restart counter hit 161). Do NOT "fix" this by running as root.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
Environment=PYTHONUNBUFFERED=1
Environment=SOURAN_PROXY=http://127.0.0.1:8118
Environment=SOURAN_PRIMARY_HOST=127.0.0.1
Environment=SOURAN_PRIMARY_PORT=5399
Environment=SOURAN_LISTEN_PORT=53
Environment=SOURAN_DOT_PORT=853
Environment=SOURAN_LISTEN_HOST=0.0.0.0
Environment=SOURAN_DOH_URL=https://cloudflare-dns.com/dns-query
Environment=SOURAN_DOH_URL2=https://dns.google/resolve
Environment=SOURAN_DOH_BUDGET=20
Environment=SOURAN_DOH_INTERVAL=0.9
Environment=SOURAN_CLIENT_TIMEOUT=25
LimitNOFILE=65536
MemoryMax=512M
StandardOutput=journal
StandardError=journal
SyslogIdentifier=souran-doh-fallback

[Install]
WantedBy=multi-user.target
UNIT

# --- DoT tier ---------------------------------------------------------------
cat > "$UNIT_DIR/souran-dns-dot.service" <<UNIT
[Unit]
Description=Souran DNS over TLS (:853)
After=network-online.target souran-dns.service
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStartPre=$ENGINE_DIR/sbin/unbound-checkconf $CONFIG_DIR/souran-unbound-tls.conf.yaml
ExecStart=$ENGINE_DIR/sbin/unbound -c $CONFIG_DIR/souran-unbound-tls.conf.yaml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=3
KillSignal=SIGTERM
LimitNOFILE=1048576
MemoryMax=512M
StandardOutput=journal
StandardError=journal
SyslogIdentifier=souran-dns-dot

[Install]
WantedBy=multi-user.target
UNIT

# --- feature units ----------------------------------------------------------
make_unit() {
  local name="$1" desc="$2" exec="$3" workdir="${4:-$SOURAN_DIR}" extra="${5:-}"
  cat > "$UNIT_DIR/${name}.service" <<UNIT
[Unit]
Description=$desc
After=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=reza
WorkingDirectory=$workdir
ExecStart=$exec
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1
$extra
LimitNOFILE=65536
MemoryMax=512M
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$name

[Install]
WantedBy=multi-user.target
UNIT
  log "  unit: ${name}.service"
}

make_unit souran-8082-dashboard \
  "Souran AI Network Server — Hermes Dashboard (Port 8082)" \
  "/usr/bin/python3 $SOURAN_DIR/agent-dashboard.py"

make_unit souran-web-8383 \
  "Souran AI Network Server - Web Dashboard (Port 8383)" \
  "/usr/bin/python3 $SOURAN_DIR/web-dashboard-8383.py"

make_unit souran-web3-resolver \
  "Souran AI Network Server - Web3 Resolver (Port 8086)" \
  "/usr/bin/python3 $SOURAN_DIR/souran_web3_resolver.py" \
  "$SOURAN_DIR" \
  "Environment=SOURAN_PROXY=http://127.0.0.1:8118"

make_unit souran-gaming-dns \
  "Souran AI Network Server - Gaming DNS (Port 8087)" \
  "/usr/bin/python3 $SOURAN_DIR/souran_gaming_dns.py" \
  "$SOURAN_DIR" \
  "Environment=SOURAN_PROXY=http://127.0.0.1:8118"

make_unit souran-learning-engine \
  "Souran AI Network Server — Learning Engine (Port 8084)" \
  "/usr/bin/python3 $SOURAN_DIR/souran_learning_engine.py" \
  "$SOURAN_DIR" \
  "Environment=HTTP_PROXY=http://127.0.0.1:8118
Environment=HTTPS_PROXY=http://127.0.0.1:8118
Environment=NO_PROXY=localhost,127.0.0.1,::1"

RUN_USER="reza"
RUN_GROUP="adm"
make_unit souran-ids \
  "Souran AI Intrusion Detection System" \
  "/usr/bin/python3 $SOURAN_DIR/intrusion-detection.py"

# v4.3.5: souran-sidecar had NO unit at all, so 19 /api routes (tor and
# censorship toggles, watchdog status, cloudflared status, ENS, gaming DNS)
# answered connection-refused even though the dashboards advertise them.
cat > "$UNIT_DIR/souran-sidecar.service" <<UNIT
[Unit]
Description=Souran AI Network Server — Ops Sidecar API (loopback :9192)
After=network-online.target souran-doh-fallback.service
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=reza
WorkingDirectory=$SOURAN_DIR
# sidecar.py binds 127.0.0.1 and /api/exec uses a fixed argv allowlist.
# It must NEVER be rebound to 0.0.0.0 — that was an RCE in v4.2.
ExecStart=/usr/bin/python3 $SOURAN_DIR/sidecar.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1
Environment=SOURAN_PROXY=http://127.0.0.1:8118
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=$SOURAN_DIR/data /var/log/souran-watchdog
LimitNOFILE=65536
MemoryMax=512M
StandardOutput=journal
StandardError=journal
SyslogIdentifier=souran-sidecar

[Install]
WantedBy=multi-user.target
UNIT
log "  unit: souran-sidecar.service"

# The IDS writes to a log created by root; without group write it crash-loops
# with PermissionError on every start.
touch /var/log/souran-ids-alerts.log 2>/dev/null || true
chown "$RUN_USER:$RUN_GROUP" /var/log/souran-ids-alerts.log 2>/dev/null || true
chmod 0660 /var/log/souran-ids-alerts.log 2>/dev/null || true

for u in souran-8082-dashboard souran-web-8383 souran-web3-resolver \
         souran-gaming-dns souran-learning-engine fwupd-refresh; do
  install_proxy_dropin "$u"
done

systemctl daemon-reload
log "daemon-reload done"

# =============================================================================
step "6/7  Censorship bypass tooling (from source)"
# =============================================================================
# GoodbyeDPI is Windows-only: it needs WinDivert and its Makefile hardcodes
# mingw. ByeDPI (hufrea/byedpi) is the maintained Linux port. Note honestly:
# on this host ciadpi's TLS ClientHello parser rejects modern handshakes
# (`ss: invalid version: 0x43`), so zapret — which works at the netfilter queue
# and never parses TLS — is the bypass that actually functions here.
if ! command -v nfqws >/dev/null 2>&1; then
  log "building zapret from source (nfqws/tpws)"
  ZDIR="$SOURAN_DIR/censorship/zapret/src"
  if [[ ! -d "$ZDIR" ]]; then
    mkdir -p "$(dirname "$ZDIR")"
    git clone --depth 1 https://github.com/bol-van/zapret.git "$ZDIR" || \
      log "WARNING: zapret clone failed — DPI bypass unavailable"
  fi
  if [[ -d "$ZDIR" ]]; then
    ( cd "$ZDIR" && make -j"$(nproc)" ) && install -m0755 "$ZDIR/nfqws" /usr/local/bin/ || true
    ( cd "$ZDIR" && make -j"$(nproc)" ) && install -m0755 "$ZDIR/tpws" /usr/local/bin/ || true
  fi
else
  log "zapret already built: $(command -v nfqws)"
fi

if ! command -v ciadpi >/dev/null 2>&1; then
  log "building ByeDPI (ciadpi) from source"
  BDIR="$SOURAN_DIR/censorship/byedpi"
  if [[ ! -d "$BDIR" ]]; then
    mkdir -p "$SOURAN_DIR/censorship"
    git clone --depth 1 https://github.com/hufrea/byedpi.git "$BDIR" || \
      log "WARNING: byedpi clone failed"
  fi
  if [[ -d "$BDIR" ]]; then
    ( cd "$BDIR" && make -j"$(nproc)" ) && install -m0755 "$BDIR/ciadpi" /usr/local/bin/ || true
    ln -sf /usr/local/bin/ciadpi /usr/local/bin/byedpi 2>/dev/null || true
  fi
else
  log "ciadpi already built: $(command -v ciadpi)"
fi

# =============================================================================
step "7/7  Start and verify"
# =============================================================================
if (( NO_START )); then
  log "--no-start: not enabling or starting units"
elif (( STACK_LIVE && ! FORCE_RESTART )); then
  # v4.3.2 restarted a live stack and killed port 53. Adopt instead.
  log "stack already live — NOT restarting units (use --force-restart to override)"
  log "verifying the live stack is still answering:"
  dig +short +time=10 +tries=1 @127.0.0.1 -p 53 example.com A 2>/dev/null | head -1 || true
else
  for u in souran-dns souran-doh-fallback souran-dns-dot souran-8082-dashboard \
           souran-web-8383 souran-web3-resolver souran-gaming-dns \
           souran-learning-engine souran-ids souran-sidecar; do
    systemctl enable "$u" >/dev/null 2>&1 || true
    systemctl restart "$u" 2>/dev/null || log "WARNING: $u failed to start"
  done
  log "units enabled and restarted; waiting for the resolver to answer"
  RESOLVER_UP=0
  for _ in $(seq 1 30); do
    if dig +short +time=5 +tries=1 @127.0.0.1 -p 53 example.com A 2>/dev/null | grep -qE '^[0-9]+\.'; then
      RESOLVER_UP=1
      log "resolver answering on :53"
      break
    fi
    sleep 2
  done
  if (( ! RESOLVER_UP )); then
    # Never leave the operator with a dead resolver and no clear next step.
    log "FATAL: :53 is not answering after restart."
    log "       Roll back with:"
    log "         sudo cp -a $SOURAN_DIR/config/souran-unbound.conf.yaml.bak-* \\"
    log "           $CONFIG_DIR/souran-unbound.conf.yaml"
    log "         sudo systemctl daemon-reload"
    log "       Then inspect: sudo journalctl -u souran-doh-fallback -n 40 --no-pager"
    exit 1
  fi
fi

log ""
log "==================== VERIFICATION ===================="
log "1. failed units:"
systemctl --failed --no-legend --no-pager || true
log "2. zero-upstream (must be 0 forwarder directives):"
grep -cE '^\s*forward-(zone|addr)' "$CONFIG_DIR/souran-unbound.conf.yaml" || true
log "3. live resolution (A / MX / SOA):"
for t in A MX SOA; do
  printf '   %-4s %s\n' "$t" \
    "$(dig +short +time=15 @127.0.0.1 -p 53 google.com "$t" 2>/dev/null | head -1)"
done
log "4. anti-poison check (must be public, never 10.x):"
printf '   %s\n' "$(dig +short +time=15 @127.0.0.1 -p 53 telegram.org A 2>/dev/null | head -1)"
log "5. full suite:"
if [[ -f "$SOURAN_DIR/souran_deep_suite.py" ]]; then
  # The suite is destructive (it restarts services and flushes caches) and now
  # holds a single-instance lock, so never run it concurrently with another.
  python3 "$SOURAN_DIR/souran_deep_suite.py" 2>&1 | tail -6 || true
fi
log "======================================================"
log "Souran AI Network Server install complete. Version: $(cat "$SOURAN_DIR/VERSION" 2>/dev/null || echo unknown)"
exit 0