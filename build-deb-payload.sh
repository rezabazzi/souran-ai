#!/usr/bin/env bash
# Souran v5.0.0 — build the .deb payload staging tree.
#
# Runs before dpkg-buildpackage. `debian/rules clean` removes debian/opt,
# so the staging has to be regenerated on every build rather than committed.
#
# Two things this deliberately EXCLUDES:
#   1. TLS private keys (config/*.key). A distributable package must never
#      carry the build host's live private keys; the postinst generates
#      fresh ones on the target.
#   2. engine/unbound-src (96 MB of vendored upstream source). It is used
#      to COMPILE the resolver during the build, but the compiled result is
#      what ships — not 96 MB of someone else's source tree.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# Destination is overridable so the same staging works for both
# `dpkg-buildpackage` (which wants debian/tmp) and a manual dpkg-deb build.
DEB="${1:-$ROOT/debian}"
LIBDIR="usr/lib"   # usrmerge: /lib is a symlink to /usr/lib on Ubuntu 24.04+
STAGE="$ROOT/.souran-stage"
DEST="$DEB/opt/souran-ai"

echo "souran-deb: staging payload"

rm -rf "$DEB/opt" "$DEB/lib" "$STAGE"
mkdir -p "$DEST" "$DEB/$LIBDIR/systemd/system" "$DEST/logs"

# --- Python modules, metadata, control scripts --------------------------
cp -a ./*.py "$DEST/"
# README.md and CHANGELOG.md are deliberately NOT shipped in the payload.
#
# dpkg unpacks straight over /opt/souran-ai, and here the source tree IS
# the deployed tree -- so shipping docs means every `dpkg -i` overwrites
# the working copy with whatever was on disk at build time. That is data
# loss, not a cosmetic issue: it silently destroyed a 12 KB README across
# two consecutive installs and left the stale v0.1.0 text in place with no
# error anywhere.
#
# Documentation belongs in the repository and on the package's own docs
# page, not in a payload that clobbers the user's tree. dh_installdocs
# already handles the /usr/share/doc copy via debian/copyright.
for f in VERSION souran-toggle toggles.conf \
         install-souran.sh souran-enable-all \
         souran_auth.py souran_features.py souran_portmap.py \
         souran_technitium.py souran_dashboard.py souran_client.py \
         souran_dns_rr.py; do
    # shellcheck disable=SC2086
    [ -e "$f" ] && cp -a "$f" "$DEST/" || true
done

# --- first-party trees --------------------------------------------------
for d in agent anticompress bin scripts src systemd web tests watchdog; do
    # shellcheck disable=SC2086
    [ -d "$d" ] && cp -a "$d" "$DEST/"
done

# --- engine: compiled resolver + root anchors, NOT the source tree -----
mkdir -p "$DEST/engine/unbound"
for d in sbin etc lib; do
    [ -d "engine/unbound/$d" ] && cp -a "engine/unbound/$d" "$DEST/engine/unbound/"
done
for f in root.hints unbound-root.key; do
    [ -f "engine/$f" ] && cp -a "engine/$f" "$DEST/engine/" || true
done

# --- config: yaml + public certs only ----------------------------------
mkdir -p "$DEST/config"
cp -a config/*.yaml "$DEST/config/" 2>/dev/null || true
cp -a config/*.pem  "$DEST/config/" 2>/dev/null || true

# --- firewall ruleset + control tooling ---------------------------------
cp -a config/souran-firewall.nft "$DEST/config/" 2>/dev/null || true
for f in souran-firewall.sh souran-feature-apply.sh souran-feature-executor.sh \
         souran-certgen.sh; do
    [ -f "$f" ] && cp -a "$f" "$DEST/" || true
done

# --- unbound version gate ---------------------------------------------
# The resolver binary and the vendored source MUST agree. A payload that
# ships a 1.24.2 binary while claiming to build from source would be
# both misleading and, since 1.24.2 is affected by CVE-2026-85501
# (ReTrap DNSSEC algorithmic-complexity DoS), vulnerable.
UNBOUND_EXPECTED="1.26.2"
if [ -x "$DEST/engine/unbound/sbin/unbound" ]; then
    got="$("$DEST/engine/unbound/sbin/unbound" -V 2>/dev/null | head -1 \
          | awk '{print $2}')"
    if [ "$got" != "$UNBOUND_EXPECTED" ]; then
        echo "souran-deb: REFUSING — expected unbound $UNBOUND_EXPECTED," >&2
        echo "             payload contains ${got:-unknown}" >&2
        exit 1
    fi
    echo "souran-deb: unbound $got (CVE-2026-85501 patched)"
fi

# --- censorship config, dns config --------------------------------------
if [ -d censorship/config ]; then
    mkdir -p "$DEST/censorship"
    cp -a censorship/config "$DEST/censorship/"
fi
if [ -d dns/config ]; then
    mkdir -p "$DEST/dns"
    cp -a dns/config "$DEST/dns/"
fi

# --- systemd units ------------------------------------------------------
shopt -s nullglob
for u in /etc/systemd/system/souran-*.service \
         /etc/systemd/system/souran-backup.timer \
         /etc/systemd/system/souran-feature-executor.service \
         /etc/systemd/system/souran-feature-executor.timer \
         /etc/systemd/system/souran-firewall.service \
         /etc/systemd/system/socks-bridge.service; do
    cp -a "$u" "$DEB/$LIBDIR/systemd/system/"
done
shopt -u nullglob

# libunbound.la is a libtool build artefact. It records -l flags from the
# BUILD host's linker line, which lintian reads as undeclared shared-library
# dependencies and which is meaningless on the target. The .so is what runs.
find "$DEST/engine/unbound/lib" \( -name '*.la' -o -name 'libunbound.a' \) -delete 2>/dev/null || true

# Strip the build-host RUNPATH from the vendored unbound binaries. They were
# linked with -rpath /opt/souran-ai/engine/unbound/lib, which is a custom
# search path lintian rightly rejects and which silently breaks if the tree
# moves. The system loader path resolves the same libraries.
if command -v chrpath >/dev/null 2>&1; then
    for b in "$DEST"/engine/unbound/sbin/*; do
        [ -x "$b" ] && chrpath -d "$b" 2>/dev/null || true
    done
else
    echo "souran-deb: chrpath not installed, leaving RUNPATH as built"
fi

# Normalise permissions on shipped executables. Several scripts in the tree
# were left non-executable, so lintian flags them and, more importantly,
# `souran-enable-all` and friends cannot be invoked directly after install.
find "$DEST" -type f \( -name '*.sh' -o -name '*.py' \) -exec chmod 0755 {} + 2>/dev/null || true
chmod 0755 "$DEST/souran-enable-all" "$DEST/souran-toggle" 2>/dev/null || true
chmod 0644 "$DEST"/VERSION "$DEST"/*.md 2>/dev/null || true

mkdir -p "$DEST/run/feature-intents"
chmod 0755 "$DEST/run" "$DEST/run/feature-intents"
find "$DEST/run/feature-intents" -type f -delete 2>/dev/null || true

touch "$DEST/logs/.keep"

# --- scrub --------------------------------------------------------------
find "$DEB/opt" "$DEB/$LIBDIR" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "$DEB/opt" "$DEB/$LIBDIR" -name '*.pyc' -delete 2>/dev/null || true
find "$DEB/opt" -name '*.bak'      -delete 2>/dev/null || true
find "$DEB/opt" -name '*.bak-*'    -delete 2>/dev/null || true
find "$DEB/opt" -name '*.pre[0-9]*' -delete 2>/dev/null || true

# Hard fail if a private key ever made it into the payload. The root
# trust anchor (unbound-root.key) is public data and is allowed.
# Hard fail if a private key or a queued intent ever reaches the payload.
#
# Note the `find ... -print` form: without an explicit -print, an empty
# result made the second append contribute a bare newline, and
# `[ -n "$STRAY" ]` was then true for an EMPTY string -- so the guard
# refused every build while printing nothing. Filtering empty lines with
# grep -v '^$' and testing the result is what makes it reliable.
STRAY="$( {
    find "$DEB/opt" -name '*.key' ! -name 'unbound-root.key' -print 2>/dev/null
    find "$DEB/opt" -path '*/feature-intents/*' -type f -print 2>/dev/null
} | grep -v '^$' || true)"
if [ -n "$STRAY" ]; then
    echo "souran-deb: REFUSING TO PACKAGE — private keys or queued" >&2
    echo "             intents staged in the payload:" >&2
    echo "$STRAY" >&2
    exit 1
fi

echo "souran-deb: staged $(du -sh "$DEST" | cut -f1), $(find "$DEST" -type f | wc -l) files, no private keys"
