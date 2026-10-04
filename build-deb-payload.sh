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
for f in VERSION CHANGELOG.md README.md souran-toggle toggles.conf \
         install-souran.sh souran-enable-all; do
    [ -e "$f" ] && cp -a "$f" "$DEST/" || true
done

# --- first-party trees --------------------------------------------------
for d in agent anticompress bin scripts src systemd web tests; do
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

touch "$DEST/logs/.keep"

# --- scrub --------------------------------------------------------------
find "$DEB/opt" "$DEB/$LIBDIR" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "$DEB/opt" "$DEB/$LIBDIR" -name '*.pyc' -delete 2>/dev/null || true
find "$DEB/opt" -name '*.bak'      -delete 2>/dev/null || true
find "$DEB/opt" -name '*.bak-*'    -delete 2>/dev/null || true
find "$DEB/opt" -name '*.pre[0-9]*' -delete 2>/dev/null || true

# Hard fail if a private key ever made it into the payload. The root
# trust anchor (unbound-root.key) is public data and is allowed.
STRAY="$(find "$DEB/opt" -name '*.key' ! -name 'unbound-root.key' 2>/dev/null || true)"
if [ -n "$STRAY" ]; then
    echo "souran-deb: REFUSING TO PACKAGE — private keys staged:" >&2
    echo "$STRAY" >&2
    exit 1
fi

echo "souran-deb: staged $(du -sh "$DEST" | cut -f1), $(find "$DEST" -type f | wc -l) files, no private keys"
