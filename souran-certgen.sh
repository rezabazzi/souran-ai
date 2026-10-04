#!/usr/bin/env bash
# =====================================================================
# SOURAN AI NETWORK SERVER v5.1.0 — TLS CERTIFICATE ISSUER
# =====================================================================
#
# WHY THIS FILE EXISTS
# --------------------
# The DoT certificate shipped by the postinst was generated as a bare
# self-signed leaf:
#
#   openssl req -x509 -newkey rsa:2048 -nodes \
#       -subj "/CN=souran.local/..." -keyout doh.key -out doh.pem
#
# Measured on the live certificate:
#
#   subject=CN=souran.local, O=Souran AI, C=IR
#   No extensions in certificate          <-- no subjectAltName
#
# That certificate is unusable by every client that matters:
#
#   Android "Private DNS" (RFC 7858) validates the hostname against the
#   SAN list and has no override for a self-signed CA in the system store;
#   the setting simply fails to connect.
#   Windows 11 "DNS over HTTPS" validates the same way.
#   macOS `networksetup -setdnsservers` plus a trusted root has the same
#   requirement.
#   Chrome/Firefox secure DNS will accept a user-added CA, but a leaf with
#   no SAN is rejected by the TLS stack before that ever matters.
#
# So encrypted DNS — the feature this whole project exists to provide —
# could not actually be turned on by a phone or a PC.
#
# WHAT THIS DOES
# --------------
# Creates a proper two-level PKI:
#
#   souran-ca.key / souran-ca.pem        local root CA  (10 years)
#   doh.key      / doh.pem               leaf cert for the DoT/DoH names
#   souran.key   / souran.pem            alias kept for the DoT server
#
# The leaf carries subjectAltName entries for every name a client might
# use, so one certificate works for the LAN IP, the WireGuard address and
# every public domain this operator owns.
#
# Installing the CA on a client is a deliberate, one-time trust decision by
# the operator -- that is the correct model, not a weakness: the point of
# DoT is that the channel is authenticated to YOUR resolver, not to a
# public CA.
#
# Usage:
#   souran-certgen.sh issue [name ...]   (re)issue the leaf, default SANs
#   souran-certgen.sh show               print subjects/SANs/expiry
#   souran-certgen.sh ca                 print the CA certificate to install
#   souran-certgen.sh export-client <dir>  write a client trust bundle
# =====================================================================
set -euo pipefail

DIR=/opt/souran-ai/config
CA_KEY="$DIR/souran-ca.key"
CA_PEM="$DIR/souran-ca.pem"
LEAF_KEY="$DIR/doh.key"
LEAF_PEM="$DIR/doh.pem"

# Every name a client could plausibly use to reach this resolver.
# The LAN address and the WireGuard address are included deliberately:
# a phone on the same Wi-Fi should be able to use the resolver's IP
# directly, and TLS still has to validate.
DEFAULT_NAMES=(
    "mordaddns.ir"
    "dns.mordaddns.ir"
    "cafenetmordad.ir"
    "dns.cafenetmordad.ir"
    "sitet.top"
    "dns.sitet.top"
    "souran.local"
    "localhost"
    "127.0.0.1"
    "10.103.26.86"     # this host's LAN address
    "10.66.66.1"       # WireGuard interface
)

die() { echo "error: $*" >&2; exit 1; }

ensure_ca() {
    if [ -s "$CA_PEM" ] && [ -s "$CA_KEY" ]; then
        return 0
    fi
    echo "==> creating local root CA (10 years)"
    openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
        -keyout "$CA_KEY" -out "$CA_PEM" \
        -subj "/O=Souran AI Network Server/OU=Souran DNS/CN=Souran DNS Root CA" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=hash" 2>/dev/null
    chmod 600 "$CA_KEY"
    chmod 644 "$CA_PEM"
}

cmd_issue() {
    local names=("$@")
    [ ${#names[@]} -gt 0 ] || names=("${DEFAULT_NAMES[@]}")

    ensure_ca

    local san=""
    for n in "${names[@]}"; do
        # An IP literal must go in IP SAN, a name in DNS SAN. Putting an
        # IP in DNS SAN is a classic mistake and is silently ignored.
        if [[ "$n" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            san+="IP:$n,"
        elif [[ "$n" == *:* ]]; then
            san+="IP:$n,"
        else
            san+="DNS:$n,"
        fi
    done
    san="${san%,}"

    local cnf
    cnf=$(mktemp)
    trap 'rm -f "$cnf"' RETURN
    cat >"$cnf" <<EOF
[req]
distinguished_name = dn
prompt = no
[dn]
O  = Souran AI Network Server
OU = Souran DNS
CN = mordaddns.ir
[ext]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = $san
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

    echo "==> issuing leaf certificate"
    echo "    SAN: $san"

    openssl req -new -newkey rsa:2048 -nodes \
        -keyout "$LEAF_KEY" -out "$DIR/.leaf.csr" \
        -config "$cnf" 2>/dev/null

    openssl x509 -req -in "$DIR/.leaf.csr" \
        -CA "$CA_PEM" -CAkey "$CA_KEY" -CAcreateserial \
        -out "$LEAF_PEM" -days 825 -sha256 \
        -extfile "$cnf" -extensions ext 2>/dev/null

    rm -f "$DIR/.leaf.csr"

    # unbound's DoT server reads these paths.
    if [ -f "$DIR/souran.key" ] || [ -f "$DIR/souran.pem" ]; then
        cp -f "$LEAF_KEY" "$DIR/souran.key"
        cp -f "$LEAF_PEM" "$DIR/souran.pem"
    fi

    # TWO consumers need this key under two different accounts:
    #   unbound (uid 993)  -> its own DoT listener on :5354
    #   reza   (uid 1000) -> the poison-proof front-end's DoT listener on :853
    # So it is root:souran-tls 0640 with BOTH accounts in that group.
    #
    # It was root:unbound, which silently broke the front-end: the postinst
    # reported certgen as failing and reza could not read the key, so the
    # :853 listener died with "Permission denied" while the certificate
    # itself was perfectly valid. A dedicated group is the fix; adding reza
    # to the `unbound` group would grant far more than key access.
    if getent group souran-tls >/dev/null 2>&1; then
        TLS_GID="souran-tls"
    else
        groupadd -r souran-tls 2>/dev/null || true
        getent group souran-tls >/dev/null 2>&1 && TLS_GID="souran-tls"
    fi
    if [ -n "${TLS_GID:-}" ]; then
        chown "root:$TLS_GID" "$LEAF_KEY" 2>/dev/null || true
        for u in reza unbound; do
            id -nG "$u" 2>/dev/null | tr ' ' '\n' | grep -qx "$TLS_GID" || \
                usermod -aG "$TLS_GID" "$u" 2>/dev/null || true
        done
    else
        chown root:root "$LEAF_KEY" 2>/dev/null || true
        echo "WARNING: could not create group souran-tls; key is root-only" >&2
    fi
    chmod 0640 "$LEAF_KEY"
    chmod 644 "$LEAF_PEM"

    # Chain file: clients that pin an intermediate need leaf+CA.
    cat "$LEAF_PEM" "$CA_PEM" > "$DIR/doh-fullchain.pem"
    chmod 644 "$DIR/doh-fullchain.pem"

    echo "==> done"
    cmd_show
}

cmd_show() {
    for f in "$CA_PEM" "$LEAF_PEM"; do
        [ -f "$f" ] || continue
        echo
        echo "--- $f"
        openssl x509 -in "$f" -noout -subject -issuer -dates 2>/dev/null
        openssl x509 -in "$f" -noout -ext subjectAltName 2>/dev/null \
            || echo "    (no SAN)"
    done
}

cmd_ca() {
    [ -f "$CA_PEM" ] || die "no CA yet — run: $0 issue"
    cat "$CA_PEM"
}

cmd_export_client() {
    local dest="${1:-/tmp/souran-client-ca}"
    mkdir -p "$dest"
    cp "$CA_PEM" "$dest/souran-dns-ca.crt"
    {
        echo "Souran AI Network Server — client trust bundle"
        echo
        echo "Install souran-dns-ca.crt as a trusted ROOT CA, then point the"
        echo "client's DNS at this resolver using DoT or DoH."
        echo
        echo "  Android : Settings > Private DNS > Custom host"
        echo "            host = mordaddns.ir  (no port field is offered;"
        echo "            Android always uses 853/DoT)"
        echo "            CA must be installed under Settings > Security >"
        echo "            Encryption & credentials > Install a certificate >"
        echo "            CA certificate."
        echo "  Windows : Settings > Network & internet > Wi-Fi > DNS server"
        echo "            assignment > Manual > <IP>, DNS over HTTPS = On"
        echo "            (Automatic certificate validation requires the CA"
        echo "             in Trusted Root Certification Authorities.)"
        echo "  macOS   : System Settings > Network > Details > DNS"
        echo "            add <IP>; install the CA in Keychain Access as"
        echo "            'Always Trust'."
        echo "  Linux   : systemd-resolved or /etc/resolv.conf -> <IP>."
        echo
        echo "Leaf certificate SANs:"
        openssl x509 -in "$LEAF_PEM" -noout -ext subjectAltName 2>/dev/null \
            | tail -n +2 | sed 's/^/  /'
    } > "$dest/README.txt"
    echo "wrote $dest/souran-dns-ca.crt and README.txt"
}

case "${1:-}" in
    issue) shift; cmd_issue "$@" ;;
    show)  cmd_show ;;
    ca)    cmd_ca ;;
    export-client) shift; cmd_export_client "${1:-/tmp/souran-client-ca}" ;;
    *) cat <<EOF
usage: $0 {issue [name ...]|show|ca|export-client [dir]}

  issue            (re)issue the DoT/DoH leaf certificate with SANs
  show             print certificate subjects, SANs and expiry
  ca               print the root CA certificate
  export-client D  write a client trust bundle + setup instructions
EOF
    exit 2 ;;
esac
