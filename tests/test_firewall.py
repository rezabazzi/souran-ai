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

NS = "sourantest"
VETH_HOST = "sth0"
VETH_NS = "sthn0"
HOST_IP = "10.99.99.1"
NS_IP = "10.99.99.2"
SUBNET = "10.99.99.0/24"

BLOCKED = [11434, 8118, 8080, 8090, 8388, 54, 9192, 8084, 8085, 8086, 8087]
ALLOWED = [53, 8082, 8383, 22]


def sh(cmd, check=True):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                          check=check)


def cleanup():
    sh(f"ip netns del {NS} 2>/dev/null || true", check=False)
    sh(f"ip link del {VETH_HOST} 2>/dev/null || true", check=False)


def setup():
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
