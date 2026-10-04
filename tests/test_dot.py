#!/usr/bin/env python3
"""
Souran v5.1.0 — encrypted DNS transport conformance test.

WHAT THIS GUARDS
----------------
Two real faults that made encrypted DNS unusable by actual clients,
both found by using a strict client (kdig, Knot's RFC 7858 tool) rather
than openssl s_client:

1. The DoT certificate had NO subjectAltName. Measured on the live cert:
   "No extensions in certificate". Android Private DNS, Windows
   DNS-over-HTTPS and macOS all validate the hostname against the SAN
   list, so the feature this project exists to provide could not be
   switched on by a phone or a PC. Fixed by a real two-level PKI
   (souran-certgen.sh): local root CA + leaf with DNS and IP SANs.

2. DoTServer built a fresh ssl.SSLContext inside get_request(), i.e. on
   every accepted socket. That discards the session cache and re-parses
   the certificate and private key on each handshake. Measured: openssl
   completed a handshake and verified the chain, while kdig failed with
   "TLS, handshake failed (Error in the pull function)" on every attempt
   against :853 -- yet the SAME client worked against the other DoT
   listener on :5354. Fixed by building the context once in __init__.

This asserts the end-to-end contract a client depends on: a real TLS
handshake, a chain that verifies against the issued CA, a hostname that
matches a SAN, and a correct DNS answer over the encrypted channel.
"""

import os
import socket
import ssl
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

CA = "/opt/souran-ai/config/souran-ca.pem"
CERT = "/opt/souran-ai/config/doh.pem"
SERVERNAME = "mordaddns.ir"
DOT_PORT = 853
DOT_PORT_ALT = 5354          # unbound's own DoT listener

# Names that must resolve over the encrypted channel.
NAMES = ["google.com", "digikala.com"]


def dot_query(name, qtype=1, port=DOT_PORT, cafile=CA,
              server_hostname=SERVERNAME, timeout=25.0):
    """Full DoT round-trip with certificate verification enforced."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile)
    ctx.check_hostname = True           # refuse a cert with no/wrong SAN
    ctx.verify_mode = ssl.CERT_REQUIRED

    raw = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s = ctx.wrap_socket(raw, server_hostname=server_hostname)
    try:
        q = b"".join(bytes([len(l)]) + l.encode()
                     for l in name.split(".")) + b"\x00"
        pkt = (struct.pack("!HHHHHH", 0x5355, 0x0100, 1, 0, 0, 0)
               + q + struct.pack("!HH", qtype, 1))
        s.sendall(struct.pack("!H", len(pkt)) + pkt)
        ln = struct.unpack("!H", s.recv(2))[0]
        data = b""
        while len(data) < ln:
            chunk = s.recv(ln - len(data))
            if not chunk:
                break
            data += chunk
        peer = s.getpeercert()
        version = s.version()
    finally:
        s.close()

    rcode = struct.unpack("!H", data[2:4])[0] & 0x0F
    ancount = struct.unpack("!H", data[6:8])[0]
    return dict(rcode=rcode, ancount=ancount, tls=version,
                peer_subject=peer, data=data)


def has_san(certfile):
    r = subprocess.run(["openssl", "x509", "-in", certfile, "-noout",
                        "-ext", "subjectAltName"],
                       capture_output=True, text=True)
    return "DNS:" in r.stdout or "IP Address:" in r.stdout


def main():
    print("=" * 70)
    print("Souran v5.1.0 — encrypted DNS (DoT) conformance")
    print("=" * 70)

    fails = []

    # --- 1. the certificate must carry SANs ----------------------------
    print("\n--- certificate must carry subjectAltName ---")
    if not os.path.exists(CA):
        print("  FAIL  no CA at", CA)
        print("        run: sudo /opt/souran-ai/souran-certgen.sh issue")
        return 1
    for f, label in ((CERT, "leaf"), (CA, "root CA")):
        ok = has_san(f) if label == "leaf" else True
        if label == "leaf":
            print(f"  {'PASS' if ok else 'FAIL'}  {label} has SANs")
            if not ok:
                fails.append("leaf certificate has no subjectAltName — "
                             "Android/Windows/macOS DoT will all refuse it")

    # --- 2. chain must verify per hostname ----------------------------
    print("\n--- chain must verify for each name a client may use ---")
    for n in (SERVERNAME, "cafenetmordad.ir", "127.0.0.1"):
        # Options must precede the certificate argument: `openssl verify`
        # treats everything after the cert path as another file to load,
        # so appending -verify_hostname here made it try to open
        # "mordaddns.ir" as a certificate and exit 2 while still printing
        # "OK" for the real cert.
        cmd = ["openssl", "verify", "-CAfile", CA]
        if n[0].isdigit():
            cmd += ["-verify_ip", n]
        else:
            cmd += ["-verify_hostname", n]
        cmd.append(CERT)
        r = subprocess.run(cmd, capture_output=True, text=True)
        ok = r.returncode == 0
        print(f"  {'PASS' if ok else 'FAIL'}  {n}")
        if not ok:
            fails.append(f"certificate does not verify for {n}")

    # --- 3. strict RFC 7858 client must work --------------------------
    print("\n--- kdig (strict RFC 7858) against :853 ---")
    kdig = subprocess.run(
        ["kdig", "@127.0.0.1", "-p", str(DOT_PORT), "+tls-ca=" + CA,
         "+tls-hostname=" + SERVERNAME, "google.com", "A"],
        capture_output=True, text=True, timeout=40)
    ok = kdig.returncode == 0 and "ANSWER SECTION" in kdig.stdout
    print(f"  {'PASS' if ok else 'FAIL'}  kdig exit={kdig.returncode}")
    if not ok:
        fails.append("kdig cannot complete a DoT query against :853")
        for line in kdig.stdout.splitlines()[:4]:
            print("        " + line)

    # --- 4. end-to-end with verification enforced ---------------------
    print("\n--- verified DoT round-trip (hostname checked) ---")
    for name in NAMES:
        try:
            r = dot_query(name)
        except ssl.SSLCertVerificationError as e:
            print(f"  FAIL  {name}: certificate rejected: {e}")
            fails.append(f"{name}: DoT cert verification failed")
            continue
        except Exception as e:
            print(f"  FAIL  {name}: {type(e).__name__}: {e}")
            fails.append(f"{name}: DoT round-trip failed")
            continue
        ok = r["rcode"] == 0 and r["ancount"] >= 1
        print(f"  {'PASS' if ok else 'FAIL'}  {name:16} "
              f"{r['tls']} rcode={r['rcode']} answers={r['ancount']}")
        if not ok:
            fails.append(f"{name}: rcode={r['rcode']} answers={r['ancount']}")

    # --- 5. the second DoT listener ----------------------------------
    print(f"\n--- second DoT listener on :{DOT_PORT_ALT} (unbound) ---")
    print("     TLS handshake + chain only: this listener has no DoH")
    print("     escalation tier, so a SERVFAIL here is expected on a")
    print("     censored link and is not a certificate fault.")
    try:
        r = dot_query("google.com", port=DOT_PORT_ALT)
        ok = True   # the handshake and verification already succeeded
        print(f"  PASS  {r['tls']} handshake + certificate verified "
              f"(rcode={r['rcode']} answers={r['ancount']})")
    except Exception as e:
        print(f"  FAIL  :{DOT_PORT_ALT} — {type(e).__name__}: {e}")
        fails.append(f":{DOT_PORT_ALT} DoT handshake failed")

    print()
    print("=" * 70)
    if fails:
        print(f"{len(fails)} FAILURE(S):")
        for f in fails:
            print("  - " + f)
        print("=" * 70)
        return 1
    print("ALL ENCRYPTED-DNS TESTS PASS")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
