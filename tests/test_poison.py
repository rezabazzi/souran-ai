#!/usr/bin/env python3
"""
Souran v5.1.0 — poison-detection conformance test.

THE BUG THIS GUARDS
-------------------
is_poison() was IPv4-only. It called socket.inet_aton(), which raises
OSError on any IPv6 literal, and a bare `except OSError: return False`
swallowed that -- so EVERY IPv6 address was classified as clean.

That matters because this network's injector also forges AAAA records. The
live example captured during the audit was:

    2001:4188:2:600:10:10:34:36
         ^^^^^^^^^^^^^^^^ Telegram's genuine allocation
                         ^^^^^^^^^^^ 10.10.34.36 -- this censor's
                                       signature IPv4 answer -- with
                                       the dots replaced by colons

The upper bits are a real allocation, so every structural check passes:
it is global, not private, not reserved, not link-local.

HOW THE FIX WORKS, AND WHY IT IS SAFE
------------------------------------
The tail four groups are zero-padded DECIMAL, so parsing them as decimal
recovers the original IPv4 address (parsing as hex yields 16.16.52.54 and
matches nothing -- an easy wrong turn that this test pins down).

False positives are the risk that matters, so the test asserts against a
set of REAL public IPv6 addresses. The check only fires when all four
tail groups are decimal digits in 0..255 AND the value they encode falls
in a range (10/8, 127/8, 172.16/12, 192.168/16, 169.254/16) that is
never routed on the public internet. A legitimate AAAA cannot do that.
"""

import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

_spec = importlib.util.spec_from_file_location(
    "sourafb", os.path.join(ROOT, "souran-doh-fallback.py"))
F = importlib.util.module_from_spec(_spec)
sys.modules["sourafb"] = F
_spec.loader.exec_module(F)

# (address, expected_is_poison, why)
CASES = [
    # ---- IPv4 injections and reserved ranges: must be flagged ---------
    ("10.10.34.36", True, "this censor's signature IPv4 injection"),
    ("10.0.0.1", True, "RFC1918 10/8"),
    ("172.16.5.5", True, "RFC1918 172.16/12"),
    ("192.168.1.1", True, "RFC1918 192.168/16"),
    ("127.0.0.1", True, "loopback"),
    ("169.254.1.1", True, "link-local"),
    ("224.0.0.1", True, "multicast"),

    # ---- real public IPv4: must NOT be flagged ------------------------
    ("8.8.8.8", False, "Google DNS"),
    ("1.1.1.1", False, "Cloudflare DNS"),
    ("185.188.104.10", False, "digikala.com, real"),
    ("149.154.167.99", False, "telegram.org, real"),
    ("216.239.38.120", False, "google.com, real"),

    # ---- the IPv6 forgery this was all about --------------------------
    ("2001:4188:2:600:10:10:34:36", True,
     "IPv6 forgery: real prefix + poison IPv4 written as decimal groups"),
    ("::ffff:10.10.34.36", True, "IPv4-mapped injection"),
    ("::ffff:192.168.1.1", True, "IPv4-mapped RFC1918"),

    # ---- IPv6 structural reserved ranges ------------------------------
    ("::1", True, "IPv6 loopback"),
    ("::", True, "IPv6 unspecified"),
    ("fe80::1", True, "IPv6 link-local"),
    ("fc00::1", True, "IPv6 unique-local"),
    ("ff02::1", True, "IPv6 multicast"),
    ("2001:db8::1", True, "documentation range"),

    # ---- REAL public IPv6: must NOT be flagged ------------------------
    # These are the false-positive guards and are the point of the test.
    ("2001:67c:4e8:f004::9", False, "telegram.org REAL AAAA"),
    ("2606:4700:4700::1111", False, "cloudflare.com REAL"),
    ("2a00:1450:4001:80f::200e", False, "google.com REAL"),
    ("2620:fe::fe", False, "facebook REAL"),
    ("2001:4860:4860::8888", False, "google DNS REAL"),
    ("2001:500:88:200::8", False, "one.one.one.one REAL"),
    ("2400:cb00::1", False, "cloudflare 2400::/12 REAL"),
    ("2a01:4f9::1", False, "hetzner REAL"),
    ("::ffff:8.8.8.8", False, "IPv4-mapped PUBLIC"),

    # ---- malformed input must not crash -------------------------------
    ("not-an-ip", False, "garbage input"),
    ("", False, "empty input"),
    ("999.999.999.999", False, "out-of-range IPv4"),
    ("2001:db8:::1", False, "malformed IPv6"),
]


def main():
    print("=" * 74)
    print("Souran v5.1.0 — poison detection (IPv4 + IPv6)")
    print("=" * 74)
    fails = []
    for ip, want, why in CASES:
        try:
            got = F.is_poison(ip)
        except Exception as exc:
            print(f"  FAIL  {ip:32} raised {type(exc).__name__}: {exc}")
            fails.append(f"{ip}: raised {type(exc).__name__}")
            continue
        ok = got == want
        print(f"  {'PASS' if ok else 'FAIL'}  {ip:32} "
              f"poison={str(got):5} (want {str(want):5}) {why}")
        if not ok:
            fails.append(f"{ip}: expected {want}, got {got}")

    print()
    print("=" * 74)
    if fails:
        print(f"{len(fails)} FAILURE(S):")
        for f in fails:
            print("  - " + f)
        print("=" * 74)
        return 1
    print(f"ALL {len(CASES)} POISON-DETECTION TESTS PASS")
    print("including 9 real public IPv6 addresses that must NOT be flagged")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    sys.exit(main())
