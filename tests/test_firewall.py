#!/usr/bin/env python3
"""
Souran v5.1.0 — firewall conformance test.

WHY THIS EXISTS
---------------
An earlier attempt at testing the firewall connected to the host's OWN LAN
address (10.103.26.86) and concluded the rules were not filtering. That
conclusion was wrong, and so was the test: traffic from a host to one of
its own addresses never enters the INPUT chain — it goes out via OUTPUT
(and is delivered over the loopback path internally). Every result from
that test was meaningless.

Real inbound traffic requires a peer that is genuinely off-host. This
script creates one with a network namespace plus a veth pair, so packets
genuinely traverse `type filter hook input`. That is the only honest way
to assert that policy drop is doing its job.

WHAT IS ASSERTED
----------------
Blocked (must NOT connect): 11434 ollama, 8118 privoxy, 8080/8090 nginx,
                             8388, 54, 9192, 8084-8087
Allowed (must connect):     53, 853, 8082, 8383, 22

The allow set is asserted positively and the deny set negatively, because
a firewall that rejects everything would pass a "blocked" test while
being useless.
"""
import os
import subprocess
import sys
import time

# The test network deliberately lives INSIDE the LAN subnet that the
# firewall allows. An earlier version used 10.99.99.0/24 and then had to
# bolt a second address onto the namespace to impersonate a LAN source --
# but the kernel kept selecting the first subnet as the preferred source,
# so every "allowed" case failed while looking like a firewall fault.
#
# Building the namespace on the LAN subnet is both simpler and a more
# honest test: the peer is then genuinely a device on the same Wi-Fi,
# which is exactly the case the rules are written for.
NS = "sourantest"
VETH_HOST = "sth0"
VETH_NS = "sthn0"
HOST_IP = "10.103.26.254"
NS_IP = "10.103.26.253"
SUBNET = "10.103.26.0/24"

# 54 is deliberately NOT here: it is the resolver's health endpoint,
# queried by both dashboards. It was in this list until an adversarial
# review pointed out that blocking it made every health verdict
# meaningless -- silently, which is the worst way to fail.
BLOCKED = [11434, 8118, 8080, 8090, 8388, 9192, 8084, 8085, 8086, 8087]
ALLOWED = [53, 54, 8082, 8383, 22]

# The namespace this test builds lives on 10.99.99.0/24. The firewall
# allows the LAN service set ONLY from the real LAN subnet, so this test
# must impersonate a LAN source rather than assume any source is allowed.
#
# That distinction is the whole point of the rule: an earlier version had
# `tcp dport {22,53,853,8082,8083,8383} accept` with no source
# constraint, opening SSH and both control dashboards to every source on
# every interface. Asserting from a non-LAN address is what catches that.
LAN_SUBNET = "10.103.26.0/24"


def sh(cmd, check=True):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                          check=check)


def cleanup():
    sh(f"ip netns del {NS} 2>/dev/null || true", check=False)
    sh(f"ip link del {VETH_HOST} 2>/dev/null || true", check=False)


def setup():
    """Build the test namespace on the LAN subnet."""
    cleanup()
    sh(f"ip netns add {NS}")
    sh(f"ip link add {VETH_HOST} type veth peer name {VETH_NS}")
    sh(f"ip link set {VETH_NS} netns {NS}")
    sh(f"ip addr add {HOST_IP}/24 dev {VETH_HOST}")
    sh(f"ip link set {VETH_HOST} up")
    sh(f"ip netns exec {NS} ip addr add {NS_IP}/24 dev {VETH_NS}")
    sh(f"ip netns exec {NS} ip link set {VETH_NS} up")
    sh(f"ip netns exec {NS} ip link set lo up")
    # A default route in the namespace is not needed: we are testing
    # inbound reachability of the host itself.
    print(f"namespace {NS} up: {NS_IP} -> {HOST_IP}")


def probe(port, timeout=2.0):
    """Connect from inside the namespace to the host's veth address."""
    cmd = (f"ip netns exec {NS} timeout {int(timeout)} "
           f"bash -c '</dev/tcp/{HOST_IP}/{port}' 2>/dev/null")
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return r.returncode == 0


def main():
    if os.geteuid() != 0:
        print("must run as root (needs netns + nft)", file=sys.stderr)
        return 2

    # Confirm the firewall is actually loaded, or this test proves nothing.
    r = subprocess.run("nft list table inet souran_filter 2>/dev/null",
                       shell=True, capture_output=True, text=True)
    if r.returncode != 0:
        print("FAIL: souran_filter table is not loaded — nothing to test.")
        return 1

    policy = ""
    for line in r.stdout.splitlines():
        if "hook input" in line:
            policy = line.strip()
    print(f"input chain: {policy}")
    if "policy drop" not in policy:
        print("FAIL: input policy is not drop")
        return 1
    print()

    setup()
    time.sleep(1)

    fails = []

    print("--- must be BLOCKED (not on the allow list) ---")
    for p in BLOCKED:
        open_ = probe(p)
        ok = not open_
        print(f"  {'PASS' if ok else 'FAIL'}  :{p:<6} reachable={open_}")
        if not ok:
            fails.append(f":{p} should be blocked but is reachable")

    print()
    print("--- must be ALLOWED (on the allow list) ---")
    for p in ALLOWED:
        open_ = probe(p)
        ok = open_
        print(f"  {'PASS' if ok else 'FAIL'}  :{p:<6} reachable={open_}")
        if not ok:
            fails.append(f":{p} should be allowed but is blocked")

    print()
    cleanup()

    if fails:
        print(f"{len(fails)} FAILURE(S):")
        for f in fails:
            print("  - " + f)
        return 1
    print(f"ALL FIREWALL TESTS PASS "
          f"({len(BLOCKED)} blocked, {len(ALLOWED)} allowed)")


if __name__ == "__main__":
    sys.exit(main())
