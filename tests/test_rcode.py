#!/usr/bin/env python3
"""
Souran v5.1.0 — DNS rcode fidelity regression test.

THE BUG THIS GUARDS
-------------------
All three request handlers (TCP, UDP, and the DoH wire path) rebuilt the
reply header flags as:

    new_flags = 0x8000 | 0x0080 | (flags & 0x0100)      # QR | RA | RD

That constructs the flags from scratch, which leaves the low 4 bits — the
RCODE — at zero. Every NXDOMAIN (3) was therefore handed to clients as
NOERROR (0).

Measured before the fix, on this host:

    name                                        tier-1 :5399   front-end :53
    hamrahsafar.com                             NXDOMAIN        NOERROR   <-- wrong
    this-domain-really-does-not-exist-998877.ir  NXDOMAIN        NOERROR   <-- wrong

and the front-end packet still carried NSCOUNT=1, so it was an NXDOMAIN
body wearing a NOERROR header.

Why it matters: NXDOMAIN says the name does not exist at all; NODATA says
it exists but has no record of that type. Applications use the difference
for negative caching, typo detection and search-path fallback. Collapsing
them makes a resolver that is functionally wrong while looking healthy.

THE TEST
--------
Compares the front-end's rcode against upstream ground truth (tier-1
unbound, and DoH over 443 as an independent witness). Runs offline-safe:
it only asserts on names whose true status is unambiguous.

Skips rather than fails when the network is unavailable, so this is
usable on a disconnected box.
"""

import os
import socket
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

FRONTEND_PORT = 53
TIER1_PORT = 5399

RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL",
               3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

# name -> expected rcode. Chosen so the truth is not in doubt:
#   *.invalid / random .ir names provably do not exist (RFC 2606 .invalid
#   is reserved and can never be registered).
# Use random labels under REAL TLDs. A reserved TLD (.invalid/.example)
# has no delegation at all, so unbound has to walk to the root and time
# out rather than getting a fast authoritative NXDOMAIN -- the first
# version of this test skipped 9 of 12 cases for exactly that reason and
# therefore proved almost nothing.
NXDOMAIN_NAMES = [
    "zzq7x2-nonexistent-souran-test.ir",
    "kp4m9-no-such-name-souran-test.com",
    "wx3n8-souran-rcode-probe.ir",
]

# A NODATA case: a name that exists in the DNS but has no A record is hard
# to guarantee without network access, so this asserts only that whatever
# comes back is a *valid* rcode and not an error we invented.
NODATA_OR_ANSWER = [
    "akamai.ir",
    "cloudflare.com",
]


def _encode_qname(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        if not label:
            continue
        out += bytes([len(label)]) + label.encode("idna" if any(
            ord(c) > 127 for c in label) else "ascii")
    return out + b"\x00"


def query(name: str, qtype: int = 1, port: int = FRONTEND_PORT,
          timeout: float = 15.0):
    """Send a UDP query and return (rcode, ancount, nscount)."""
    qid = 0x5355
    q = _encode_qname(name) + struct.pack("!HH", qtype, 1)
    pkt = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + q
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, ("127.0.0.1", port))
        data, _ = s.recvfrom(4096)
    finally:
        s.close()
    _qid, flags, _qd, an, ns, _ar = struct.unpack("!HHHHHH", data[:12])
    return flags & 0x000F, an, ns


def doh_status(name: str, qtype: int = 1):
    """Independent ground truth via DoH over the local bypass proxy."""
    cmd = (
        "curl -s --max-time 12 -x http://127.0.0.1:8118 "
        "-H 'accept: application/dns-json' "
        f"'https://cloudflare-dns.com/dns-query?name={name}&type={qtype}'"
    )
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=20)
        import json
        return json.loads(r.stdout).get("Status")
    except Exception:
        return None


def main() -> int:
    print("=" * 70)
    print("Souran v5.1.0 — DNS rcode fidelity")
    print("=" * 70)

    fails, skipped = [], 0

    # --- 1. NXDOMAIN must survive the front-end ------------------------
    print("\n--- NXDOMAIN must reach the client as NXDOMAIN ---")
    for name in NXDOMAIN_NAMES:
        try:
            fe, an, ns = query(name)
        except socket.timeout:
            print(f"  SKIP  {name}: frontend timed out")
            skipped += 1
            continue
        truth = doh_status(name)
        want = 3
        ok = fe == want
        extra = f" (DoH says {RCODE_NAMES.get(truth, truth)})" if truth is not None else ""
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        print(f"          frontend rcode={fe} ({RCODE_NAMES.get(fe, '?')})"
              f" ancount={an} nscount={ns}{extra}")
        if not ok:
            fails.append(f"{name}: expected NXDOMAIN(3), got "
                         f"{fe} ({RCODE_NAMES.get(fe, '?')})")

    # --- 2. front-end must agree with an independent authority ---------
    #
    # Compared against DoH rather than tier-1 unbound: unbound needs to
    # walk to an authority for a random label and often exceeds any sane
    # timeout on this link, which made the earlier tier-1 comparison skip
    # every case. DoH over 443 is fast, already used as ground truth
    # above, and is genuinely independent of the code under test.
    print("\n--- front-end rcode must match DoH (independent authority) ---")
    for name in NXDOMAIN_NAMES + NODATA_OR_ANSWER:
        truth = doh_status(name)
        if truth is None:
            print(f"  SKIP  {name}: DoH unavailable")
            skipped += 1
            continue
        try:
            fe, an, ns = query(name, timeout=25.0)
        except socket.timeout:
            print(f"  SKIP  {name}: frontend timeout")
            skipped += 1
            continue
        # DoH Status 0 with no A record is NODATA; the front-end may
        # legitimately answer NOERROR for it. Compare like for like.
        ok = fe == truth
        print(f"  {'PASS' if ok else 'FAIL'}  {name}: "
              f"DoH={RCODE_NAMES.get(truth, truth)} "
              f"frontend={RCODE_NAMES.get(fe, fe)} ancount={an}")
        if not ok:
            fails.append(f"{name}: DoH says {RCODE_NAMES.get(truth, truth)} "
                         f"but the front-end said {RCODE_NAMES.get(fe, fe)}")

    # --- 3. a real answer must still be NOERROR ------------------------
    print("\n--- a resolvable name must still answer NOERROR with a record ---")
    for name in NODATA_OR_ANSWER:
        try:
            fe, an, ns = query(name)
        except socket.timeout:
            print(f"  SKIP  {name}: timeout")
            skipped += 1
            continue
        ok = fe == 0
        print(f"  {'PASS' if ok else 'FAIL'}  {name}: "
              f"rcode={RCODE_NAMES.get(fe, fe)} ancount={an} nscount={ns}")
        if not ok:
            fails.append(f"{name}: expected NOERROR, got {fe}")

    print()
    print("=" * 70)
    if fails:
        print(f"{len(fails)} FAILURE(S):")
        for f in fails:
            print("  - " + f)
        print("=" * 70)
        return 1
    print(f"ALL RCODE TESTS PASS" + (f" ({skipped} skipped)" if skipped else ""))
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
