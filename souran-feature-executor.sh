#!/bin/bash
# =====================================================================
# SOURAN AI NETWORK SERVER v5.1.0 — PRIVILEGED FEATURE EXECUTOR
# =====================================================================
#
# WHY A SEPARATE EXECUTOR
# -----------------------
# The control-plane services (sidecar, both dashboards) run with
# NoNewPrivileges=yes. That is deliberate, correct hardening: it stops a
# compromised request handler from gaining privilege. But it also sets a
# kernel flag that makes the setuid bit inert, so `sudo` refuses with
# "the 'no new privileges' flag is set". This is not a sudoers problem and
# cannot be fixed from sudoers -- a child cannot lower the flag.
#
# Two earlier designs were tried and both failed for that reason:
#   1. the sidecar calling `sudo systemctl ...` directly
#   2. the sidecar calling `sudo souran-feature-apply.sh`
# Both produced rc=1 with the no-new-privileges error from inside the
# service, while the identical command worked from a shell.
#
# The resolution is to split privilege from control: the unprivileged
# process records an INTENT as a file, and this executor -- running as root
# outside that sandbox -- applies it.
#
# SECURITY PROPERTIES
# -------------------
#   - Runs as root, but only ever applies requests from the intent dir.
#   - Feature ids are validated against the allowlist in
#     souran-feature-apply.sh; an unknown id is refused there, so nothing
#     here can be used to reach an arbitrary unit.
#   - Requested filenames are ignored entirely: the executor enumerates
#     *.json in the directory itself, so no caller-supplied path is ever
#     opened.
#   - Each intent is processed once and removed; a crash mid-batch simply
#     leaves intents for the next run (at-least-once, and every action is
#     idempotent).
#   - Every action is appended to logs/feature-actions.log.
# =====================================================================
set -uo pipefail

INTENT_DIR=/opt/souran-ai/run/feature-intents
APPLY=/opt/souran-ai/souran-feature-apply.sh
LOG=/opt/souran-ai/logs/feature-actions.log
mkdir -p "$(dirname "$LOG")" "$INTENT_DIR" 2>/dev/null || true

log() {
    printf '%s EXECUTOR %s\n' "$(date -Is)" "$*" >>"$LOG" 2>/dev/null || true
}

[ -x "$APPLY" ] || { log "FATAL actuator missing"; exit 1; }

shopt -s nullglob
files=("$INTENT_DIR"/*.json)
shopt -u nullglob

if [ ${#files[@]} -eq 0 ]; then
    exit 0
fi

log "processing ${#files[@]} intent(s)"
for f in "${files[@]}"; do
    # Read the two fields we need. No eval, no sourcing, no expansion of
    # file content into a command.
    feature=$(sed -n 's/.*"feature"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$f" 2>/dev/null | head -1)
    action=$(sed -n 's/.*"action"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$f" 2>/dev/null | head -1)

    if [ -z "$feature" ] || [ -z "$action" ]; then
        log "REFUSE malformed intent $(basename "$f")"
        rm -f "$f"
        continue
    fi

    out=$("$APPLY" "$feature" "$action" 2>&1)
    rc=$?
    if [ $rc -eq 0 ]; then
        log "OK ${feature} ${action} :: ${out}"
    else
        log "FAIL ${feature} ${action} rc=${rc} :: ${out}"
    fi
    rm -f "$f"
done

# Refresh the unprivileged view of firewall/NAT state after any change.
if command -v nft >/dev/null 2>&1; then
    /opt/souran-ai/souran-firewall.sh reload >/dev/null 2>&1 || true
fi

log "batch complete"
exit 0
