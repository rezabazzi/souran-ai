#!/bin/bash
# Fetch the pinned unbound source tree.
#
# WHY THIS FETCHES A COMMIT AND NOT A VERSION
#
# The obvious recipe is "download unbound-1.26.2.tar.gz from nlnetlabs.nl".
# That does not work, and the failure is silent unless you check:
#
#     unbound-1.26.2.tar.gz  ->  HTTP 404
#     unbound-1.26.1.tar.gz  ->  HTTP 200
#
# 1.26.1 is the newest published release. This project builds a tree that
# reports itself as 1.26.2 and contains the fix for CVE-2026-85501, which
# 1.26.1 does NOT have -- see engine/PROVENANCE.md for the proof, which is
# a symbol comparison between the two trees' compiled objects.
#
# So the tree is pinned to an exact commit in NLnetLabs/unbound. That is
# strictly more precise than a version string: a version can be re-tagged,
# a commit cannot.
#
# Substituting a numbered release here would silently reintroduce the
# vulnerability. That is why the pin is a commit and why this script
# verifies the tree it produced.

set -euo pipefail

UNBOUND_REPO="https://github.com/NLnetLabs/unbound.git"
# The tree that carries the CVE-2026-85501 fix (NSEC3 hash-length
# validation). Reports itself as 1.26.2; no such release is published.
UNBOUND_COMMIT="a7fc80d8c5dd6215c52570dd281ec58d04d25eea"
UNBOUND_REPORTS="1.26.2"

DEST="${1:-/opt/souran-ai/engine/unbound-src}"
WORK="$(mktemp -d /tmp/unbound-fetch.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

log() { printf '[fetch-unbound] %s\n' "$*" >&2; }

# Egress on this network goes through Tor or a local proxy. Respect
# whatever the caller already has configured rather than hardcoding one.
PROXY_ARGS=()
if [ -n "${SOURAN_FETCH_PROXY:-}" ]; then
    PROXY_ARGS=(--proxy "$SOURAN_FETCH_PROXY")
elif [ -S /var/run/tor/socks.sock ] 2>/dev/null || \
     (exec 3<>/dev/tcp/127.0.0.1/9050) 2>/dev/null; then
    PROXY_ARGS=(--proxy socks5h://127.0.0.1:9050)
fi
[ ${#PROXY_ARGS[@]} -gt 0 ] && log "using ${PROXY_ARGS[*]}"

fetch() {
    # A full clone pulls ~200 MB of unbound history. Over Tor that does
    # not finish in any reasonable time -- measured: it ran past 800 s and
    # was still going. A shallow fetch of the single pinned commit takes
    # 20 s, which is the difference between a usable build instruction and
    # an unusable one.
    #
    # `git init` + `fetch --depth 1 <sha>` is used rather than
    # `clone --depth 1` because the commit is not a branch tip, so there
    # is no ref to shallow-clone directly.
    if [ ${#PROXY_ARGS[@]} -gt 0 ]; then
        case "${PROXY_ARGS[*]}" in
            *socks5h*)
                export ALL_PROXY="socks5h://127.0.0.1:9050"
                export GIT_PROXY_COMMAND=""
                ;;
            *)
                proxy="${PROXY_ARGS[2]:-}"
                export https_proxy="$proxy" http_proxy="$proxy"
                ;;
        esac
    fi
    mkdir -p "$WORK/unbound"
    git -C "$WORK/unbound" init --quiet
    git -C "$WORK/unbound" remote add origin "$UNBOUND_REPO"
    git -C "$WORK/unbound" fetch --quiet --depth 1 origin "$UNBOUND_COMMIT"
    git -C "$WORK/unbound" checkout --quiet FETCH_HEAD
}

log "cloning $UNBOUND_REPO"
fetch || {
    log "ERROR: could not reach $UNBOUND_REPO"
    log "       Set SOURAN_FETCH_PROXY=http://127.0.0.1:8118 (or a Tor"
    log "       SOCKS proxy) and retry. The source cannot be substituted:"
    log "       the newest release is NOT patched for CVE-2026-85501."
    exit 1
}

got="$(git -C "$WORK/unbound" rev-parse HEAD)"
if [ "$got" != "$UNBOUND_COMMIT" ]; then
    log "ERROR: checked out $got, expected $UNBOUND_COMMIT"
    exit 1
fi

# VERIFY THE FIX IS PRESENT, not just that the commit matches.
#
# A commit hash proves you fetched the tree you asked for. It does not
# prove the tree does what this project needs it to do. The guard added
# for CVE-2026-85501 is nsec3_algo_has_hashlen() in validator/val_nsec3.c;
# upstream 1.26.1 lacks it entirely.
if ! grep -q 'nsec3_algo_has_hashlen' "$WORK/unbound/validator/val_nsec3.c"; then
    log "ERROR: tree at $UNBOUND_COMMIT does NOT contain the"
    log "       CVE-2026-85501 fix (nsec3_algo_has_hashlen missing)."
    log "       Refusing to continue."
    exit 1
fi
log "CVE-2026-85501 fix present (nsec3_algo_has_hashlen)"

if [ -e "$DEST" ]; then
    log "replacing existing $DEST"
    rm -rf "$DEST"
fi
mkdir -p "$(dirname "$DEST")"
mv "$WORK/unbound" "$DEST"

# Leave a marker so build-deb-payload.sh and status output can prove where
# the tree came from without a network round trip.
cat > "$DEST/.souran-provenance" <<EOF
commit=$UNBOUND_COMMIT
reports=$UNBOUND_REPORTS
patched=CVE-2026-85501 (nsec3_algo_has_hashlen)
note=unreleased tree; 1.26.1 exists but is NOT patched. See engine/PROVENANCE.md
EOF

log "OK: $DEST at $UNBOUND_COMMIT (reports $UNBOUND_REPORTS)"