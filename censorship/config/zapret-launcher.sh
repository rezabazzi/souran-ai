#!/bin/bash
# Zapret DPI bypass launcher — Souran AI Network Server
# Rewritten 2026-10-03: the previous args (--split2, tpws --auto) do not exist
# in these self-built nfqws/tpws binaries, so the unit crash-looped every 10s.
# Flag set below is validated against `nfqws --dry-run` / `tpws --dry-run`.
set -u

BIN_NFQWS=/usr/local/bin/nfqws
BIN_TPWS=/usr/local/bin/tpws
HOSTLIST=/opt/souran-ai/censorship/config/zapret-hosts.txt
QNUM=151
TPWS_PORT=9031

log() { echo "zapret: $*" >&2; }

[ -x "$BIN_NFQWS" ] || { log "nfqws missing at $BIN_NFQWS"; exit 1; }
[ -f "$HOSTLIST" ]   || { log "hostlist missing at $HOSTLIST"; exit 1; }

# NFQUEUE engine: reads the TLS SNI out of the stream, so the hostlist is
# honoured per-connection. fakedsplit = fake packet + split the real one.
# (fake,fakedsplit is a valid combo; adding ",fooling" is rejected by this build.)
NFQWS_ARGS=(
  --qnum="$QNUM"
  --dpi-desync=fake
  --hostlist="$HOSTLIST"
  --hostlist-auto-fail-threshold=3
  --hostlist-auto-fail-time=60
)

# Transparent TCP engine (no NFQUEUE, no extra iptables rule beyond a REDIRECT).
# It only splits at TCP level, so it is scoped to the port we redirect.
TPWS_ARGS=(
  --port="$TPWS_PORT"
  --new
  --tlsrec=1
  --split-pos=1
  --disorder
  --hostlist="$HOSTLIST"
)

if ! "$BIN_NFQWS" "${NFQWS_ARGS[@]}" --dry-run >/dev/null 2>&1; then
  log "nfqws argument set rejected — refusing to start"; exit 1
fi
if ! "$BIN_TPWS" "${TPWS_ARGS[@]}" --dry-run >/dev/null 2>&1; then
  log "tpws argument set rejected — continuing with nfqws only"
  TPWS_ARGS=()
fi

log "starting nfqws (qnum=$QNUM, $(wc -l < "$HOSTLIST") hosts)"
"$BIN_NFQWS" "${NFQWS_ARGS[@]}" &
NFQWS_PID=$!

if [ ${#TPWS_ARGS[@]} -gt 0 ]; then
  log "starting tpws (port=$TPWS_PORT)"
  "$BIN_TPWS" "${TPWS_ARGS[@]}" &
  TPWS_PID=$!
else
  TPWS_PID=""
fi

# If either engine dies, take the other down so systemd restarts cleanly
# instead of leaving a half-working desync stack behind.
cleanup() {
  log "shutting down"
  kill "$NFQWS_PID" 2>/dev/null
  [ -n "$TPWS_PID" ] && kill "$TPWS_PID" 2>/dev/null
  wait 2>/dev/null
  exit 0
}
trap cleanup TERM INT

if [ -n "$TPWS_PID" ]; then
  wait -n "$NFQWS_PID" "$TPWS_PID"
else
  wait "$NFQWS_PID"
fi
log "an engine exited — restarting the pair"
cleanup