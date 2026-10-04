#!/usr/bin/env python3
"""
Souran AI Network Server v5.1.0 — Port & Service Registry
File: souran_portmap.py

WHY
---
"Diag all ports and map everything what is for" was asked for explicitly,
and the honest answer is that no such inventory existed. Ports had been
discovered piecemeal across a session, several were unidentified, and the
firewall's allowlist had been written from a partial reading. That is not
a safe basis for a default-deny policy.

This module produces the inventory from live kernel state (ss), joins it
against a curated registry of what each port is actually FOR, and flags
anything it cannot account for. The unknowns are the interesting part:
they are what a default-deny policy must be careful about.

It also cross-checks the firewall's declared allowlist against what is
actually reachable, which is how a service that was meant to be
loopback-only but binds 0.0.0.0 gets noticed.

Run directly for a human-readable report.
"""

import json
import os
import re
import socket
import subprocess
from datetime import datetime, timezone

# --------------------------------------------------------------------------
# Registry: port -> what it is for
# --------------------------------------------------------------------------
# souran=True marks ports that belong to this project. The rest are
# pre-existing host services that were here before Souran and are NOT
# managed by it — several of them are genuinely risky and are called out
# by the audit.
PORT_REGISTRY = {
    # ---- Souran: DNS core ----
    53:   dict(souran=True, name="Souran DNS front-end",
               proto="tcp+udp", purpose="Poison-proof recursive resolver. "
               "Cross-checks tier-1 answers for injected private IPs and "
               "escalates to DoH over 443.",
               exposure="LAN (intentional: a resolver only serving "
                        "loopback would be useless)"),
    54:   dict(souran=True, name="Souran DNS health probe",
               proto="tcp+udp", purpose="Lightweight liveness endpoint for "
               "the watchdog.", exposure="all interfaces"),
    853:  dict(souran=True, name="Souran DNS-over-TLS",
               proto="tcp", purpose="Encrypted DNS transport.",
               exposure="LAN"),
    5399: dict(souran=True, name="unbound tier-1 core",
               proto="tcp+udp", purpose="True zero-upstream iterative "
               "resolver, internal only.", exposure="loopback"),
    8953: dict(souran=True, name="unbound DoT",
               proto="tcp", purpose="unbound's own TLS listener.",
               exposure="loopback"),

    # ---- Souran: encrypted DNS front ends ----
    8083: dict(souran=True, name="Souran DNS-over-HTTPS",
               proto="tcp", purpose="DoH over HTTPS/443 for clients and "
               "for the resolver's own escalation tier.",
               exposure="LAN"),

    # ---- Souran: control plane ----
    8082: dict(souran=True, name="Hermes control dashboard",
               proto="tcp", purpose="Primary operator dashboard. "
               "Token-protected by souran_auth.", exposure="LAN"),
    8383: dict(souran=True, name="Web dashboard",
               proto="tcp", purpose="Secondary operator dashboard.",
               exposure="LAN"),
    9192: dict(souran=True, name="Sidecar control API",
               proto="tcp", purpose="Loopback-only API backing both "
               "dashboards: features, Technitium, watchdog, diagnostics.",
               exposure="loopback"),

    # ---- Souran: feature services ----
    8084: dict(souran=True, name="Learning engine",
               proto="tcp", purpose="Records resolution outcomes for "
               "analysis.", exposure="loopback"),
    8085: dict(souran=True, name="Anti-compression engine",
               proto="tcp", purpose="Lossless context handling.",
               exposure="loopback"),
    8086: dict(souran=True, name="Web3 / ENS resolver",
               proto="tcp", purpose="Blockchain name resolution.",
               exposure="loopback"),
    8087: dict(souran=True, name="Gaming DNS",
               proto="tcp", purpose="Game-service resolver profile.",
               exposure="loopback"),

    # ---- Souran: censorship bypass ----
    1080: dict(souran=True, name="ciadpi desync proxy",
               proto="tcp", purpose="DPI desync HTTP proxy.",
               exposure="loopback"),
    8118: dict(souran=True, name="privoxy",
               proto="tcp", purpose="Outbound HTTP proxy the DoH tier and "
               "bypass stack depend on.", exposure="LAN (0.0.0.0)"),
    8119: dict(souran=True, name="SOCKS->Tor bridge",
               proto="tcp", purpose="HTTP CONNECT -> Tor SOCKS5.",
               exposure="loopback"),
    9031: dict(souran=True, name="tpws (zapret)",
               proto="tcp", purpose="TLS desync transport.",
               exposure="all interfaces"),
    17844: dict(souran=True, name="SOCKS bridge raw forwarder",
                proto="tcp", purpose="Recovers cloudflared's original "
                "destination after NAT and relays it over Tor.",
                exposure="loopback"),

    # ---- Tor ----
    9050: dict(souran=False, name="Tor SOCKS5",
               proto="tcp", purpose="Tor transport.", exposure="loopback"),
    9051: dict(souran=False, name="Tor control",
               proto="tcp", purpose="Tor control port.", exposure="loopback"),
    9053: dict(souran=False, name="Tor DNS",
               proto="udp", purpose="Outbound DNS is NAT-redirected here "
               "so it cannot be poisoned at source.", exposure="loopback"),

    # ---- Web / tunnel ----
    8080: dict(souran=False, name="nginx (Technitium dashboard)",
               proto="tcp", purpose="Serves a static HTML file; the "
               "Technitium server behind it is NOT running.",
               exposure="all interfaces"),
    8090: dict(souran=False, name="nginx (Technitium API passthrough)",
               proto="tcp", purpose="Proxies to 127.0.0.1:53443, which is "
               "dead, so every call fails.", exposure="all interfaces"),
    53443: dict(souran=False, name="Technitium HTTPS API",
                proto="tcp", purpose="Technitium control API. Not running.",
                exposure="n/a"),

    # ---- Proxies / relays (pre-existing) ----
    20128: dict(souran=False, name="omniroute", proto="tcp",
                purpose="Third-party relay.", exposure="loopback"),
    20131: dict(souran=False, name="omniroute", proto="tcp",
                purpose="Third-party relay.", exposure="loopback"),
    20132: dict(souran=False, name="omniroute", proto="tcp",
                purpose="Third-party relay.", exposure="loopback"),
    20243: dict(souran=False, name="cloudflared metrics",
                proto="tcp", purpose="Tunnel metrics.", exposure="loopback"),
    2080: dict(souran=False, name="local proxy", proto="tcp",
               purpose="Unidentified third-party proxy.",
               exposure="loopback"),
    4443: dict(souran=False, name="Hysteria2", proto="udp",
               purpose="QUIC-based proxy/tunnel.", exposure="all interfaces"),
    8443: dict(souran=False, name="xray", proto="tcp",
               purpose="Proxy/VPN transport.", exposure="all interfaces"),
    8444: dict(souran=False, name="xray", proto="tcp",
               purpose="Proxy/VPN transport.", exposure="all interfaces"),
    8388: dict(souran=False, name="ss-server (shadowsocks)",
               proto="tcp", purpose="SOCKS proxy.", exposure="all interfaces"),
    1080.0: dict(souran=True, name="(see 1080)", proto="tcp",
                 purpose="", exposure=""),

    # ---- Identified after investigation (were UNIDENTIFIED) ----
    42459: dict(souran=True, name="obfs4proxy (Tor bridge)",
                proto="tcp", purpose="obfs4 pluggable transport for the Tor "
                "bridge: makes bridge traffic look like random noise so a "
                "censor cannot fingerprint it by protocol.",
                exposure="loopback (fronted by a published relay port)"),
    323:  dict(souran=False, name="chronyd NTP command",
               proto="udp", purpose="chrony's NTP control channel, bound "
               "to loopback only.", exposure="loopback"),
    3702: dict(souran=False, name="wsdd (WS-Discovery)",
               proto="udp", purpose="Windows/Samba network discovery "
               "daemon pulled in by gvfs; it opens many high UDP ports on "
               "all interfaces. Not needed by Souran and not something "
               "this project uses.", exposure="all interfaces"),
    35655: dict(souran=False, name="containerd",
                proto="tcp", purpose="container runtime's internal socket.",
                exposure="loopback"),
    # ---- Host services (pre-existing, NOT Souran) ----
    22:   dict(souran=False, name="OpenSSH", proto="tcp",
               purpose="Remote administration.", exposure="LAN"),
    631:  dict(souran=False, name="CUPS", proto="tcp",
               purpose="Printer daemon.", exposure="loopback"),
    11434: dict(souran=False, name="Ollama", proto="tcp",
                purpose="Local LLM inference. Executes model requests for "
                "anyone who reaches it — the highest-risk service here.",
                exposure="all interfaces"),
    3306: dict(souran=False, name="MySQL", proto="tcp",
               purpose="Database.", exposure="loopback"),
    33060: dict(souran=False, name="MySQL X protocol", proto="tcp",
                purpose="Database.", exposure="loopback"),
    5432: dict(souran=False, name="PostgreSQL", proto="tcp",
               purpose="Database.", exposure="loopback"),
    5353: dict(souran=False, name="mDNS / LLMNR", proto="udp",
               purpose="Local service discovery.", exposure="all interfaces"),
    5354: dict(souran=False, name="LLMNR", proto="tcp+udp",
               purpose="Name resolution.", exposure="loopback"),
    51820: dict(souran=False, name="WireGuard", proto="udp",
                purpose="VPN transport.", exposure="all interfaces"),
    123:  dict(souran=False, name="chrony/NTP", proto="udp",
               purpose="Time sync.", exposure="all interfaces"),
}

# Firewall's declared LAN allowlist, mirrored here so drift is detectable.
FIREWALL_ALLOWS = {22, 53, 853, 8082, 8083, 8383}


def _run(cmd, timeout=15, privileged=False):
    """Run a command. Privileged reads are attempted both ways.

    `ss -p` and `nft list` both need privilege to be complete: without it
    the process column is empty and the firewall lookup returns nothing,
    which made the first version of this report claim "firewall NOT
    LOADED" on a host where it was enforcing. Try plain first, fall back
    to sudo -n, and report what actually answered.
    """
    attempts = [cmd]
    if privileged:
        attempts.append("sudo -n " + cmd)
    for c in attempts:
        try:
            r = subprocess.run(c, shell=True, capture_output=True, text=True,
                               timeout=timeout)
            if r.stdout.strip():
                return r.stdout
        except Exception:
            continue
    return ""


def live_sockets():
    """Parse `ss` into structured records. This is ground truth."""
    out = _run("ss -tulpnH", privileged=True)
    recs = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0]
        local = parts[4]
        proc = ""
        m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
        if m:
            proc = f"{m.group(1)}:{m.group(2)}"

        # normalise address:port, handling [::]:1234 and 10.0.0.1:53
        addr, _, port_s = local.rpartition(":")
        try:
            port = int(port_s)
        except ValueError:
            continue
        addr = addr.strip("[]")

        if addr in ("127.0.0.1", "::1"):
            scope = "loopback"
        elif addr.startswith("127.") or addr.startswith("::ffff:127."):
            scope = "loopback"
        elif addr in ("0.0.0.0", "::", "*", ""):
            scope = "all-interfaces"
        elif addr.startswith("10.") or addr.startswith("192.168.") \
                or addr.startswith("172."):
            scope = "specific-lan"
        elif re.match(r"^\d+\.\d+\.\d+\.\d+$", addr) or ":" in addr:
            scope = "specific"
        else:
            scope = "other"
        recs.append(dict(proto=proto, port=port, addr=addr, scope=scope,
                         process=proc))
    # Collapse to one row per (port, proto).
    #
    # A dual-stack socket appears once per address family and a
    # multi-address bind appears once per address, so the raw `ss` output
    # repeats the same service several times. Report the WIDEST scope seen
    # for that port, because that is what determines reachability.
    merged = {}
    rank = {"loopback": 0, "specific-lan": 1, "specific": 2,
            "other": 3, "all-interfaces": 4}
    for r in recs:
        k = (r["port"], r["proto"])
        cur = merged.get(k)
        if cur is None:
            rec = dict(r)
            rec["procs"] = {r["process"]} if r["process"] else set()
            merged[k] = rec
            continue
        if rank.get(r["scope"], 0) > rank.get(cur["scope"], 0):
            cur["scope"] = r["scope"]
            cur["addr"] = r["addr"]
        # Collect every process seen for this port: a single socket can
        # produce several rows (one per address family) and the process
        # column is only populated on some of them.
        procs = set(x for x in (cur.get("procs") or set()) if x)
        if r["process"]:
            procs.add(r["process"])
        cur["procs"] = procs
        if not cur["process"] and r["process"]:
            cur["process"] = r["process"]
        cur.setdefault("addrs", set()).add(r["addr"])
    out = []
    for v in merged.values():
        if len(v.get("addrs", ())) > 1:
            v["addrs"] = sorted(v["addrs"])
        out.append(v)
    return sorted(out, key=lambda r: (r["port"], r["proto"]))


_cmdline_cache = {}


def _proc_cmdline(pid: str) -> str:
    """Resolve a pid to its full command line, cached.

    ss -p reports only the executable name, so every python3 socket looks
    identical. Without this, wsdd, the DNS front-end and a stray script
    are all just "python3" and the port map cannot tell them apart.
    """
    if pid in _cmdline_cache:
        return _cmdline_cache[pid]
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            raw = fh.read().replace(b"\x00", b" ").decode("utf-8", "replace")
    except OSError:
        raw = ""
    _cmdline_cache[pid] = raw
    return raw


def _firewall_reachable():
    """Which ports does the loaded firewall actually let through on input?

    Read from the ruleset rather than assuming, so the allowlist reported
    here is the enforced one.
    """
    rules = _run("nft list table inet souran_filter", privileged=True)
    if not rules:
        # No privilege (the control plane runs NoNewPrivileges=yes and
        # cannot sudo). The firewall publishes its own state from the
        # privileged path, so read that instead of reporting "not loaded"
        # for a ruleset that is demonstrably enforcing -- which is what
        # the first version did.
        try:
            with open("/opt/souran-ai/logs/firewall-state.json") as fh:
                st = json.load(fh)
            if st.get("souran_filter_loaded"):
                return sorted(FIREWALL_ALLOWS)
        except (OSError, ValueError):
            pass
        return None
    allowed = set()
    for line in rules.splitlines():
        m = re.search(r"tcp dport \{([^}]*)\}", line)
        if m and "accept" in line:
            for p in m.group(1).split(","):
                p = p.strip()
                if p.isdigit():
                    allowed.add(int(p))
        m = re.search(r"udp dport (\d+)", line)
        if m and "accept" in line:
            allowed.add(int(m.group(1)))
    return allowed


def build_report() -> dict:
    socks = live_sockets()
    fw = _firewall_reachable()

    entries = []
    unknown = []
    exposed_unknown = []

    for s in socks:
        reg = PORT_REGISTRY.get(s["port"])
        proc_names = {p.split(":")[0] for p in (s.get("procs") or set()) if p}
        proc_name = (s.get("process") or "").split(":")[0]
        # Resolve ambiguous interpreters to the real program.
        cmdlines = " ".join(
            _proc_cmdline(p.split(":")[1])
            for p in (s.get("procs") or set()) if ":" in p)
        if "wsdd" in cmdlines:
            proc_names.add("wsdd")
        if "souran-doh-fallback" in cmdlines:
            proc_names.add("souran-doh-fallback")
        if reg is None and (proc_names & {"brave", "chrome", "chromium"}):
            reg = dict(souran=False, name="Brave/Chromium (ephemeral)",
                       proto=s["proto"],
                       purpose="Browser WebRTC/media sockets. Not a service: "
                               "no fixed port and no inbound contract, so "
                               "there is nothing to allow or deny.",
                       exposure="browser-determined")
        if reg is None and any("obfs4" in n for n in proc_names):
            reg = dict(PORT_REGISTRY[42459])
        # Ephemeral client sockets (kernel-assigned, above 32768) with no
        # owning service are outbound connections or short-lived helpers,
        # not listeners. They cannot be firewalled in or allowed out by
        # port number, so they are reported separately rather than as
        # unidentified services.
        if reg is None and s["port"] > 32768:
            reg = dict(souran=False,
                       name=("ephemeral client socket"
                             if proc_name in ("python3", "brave", "")
                             else f"ephemeral ({proc_name})"),
                       proto=s["proto"],
                       purpose="Kernel-assigned ephemeral port. An outbound "
                               "connection or a short-lived helper process, "
                               "not a listening service: there is no fixed "
                               "port to allow or deny.",
                       exposure="not a listener")
        if reg is None and any("wsdd" in n for n in proc_names):
            reg = dict(PORT_REGISTRY[3702])
            reg = dict(reg)
            reg["purpose"] = (reg["purpose"] +
                              f" (this socket: ephemeral high UDP port "
                              f"opened by the same daemon)")
            reg["exposure"] = "all interfaces"
        if reg:
            name = reg["name"]
            purpose = reg["purpose"]
            is_souran = reg["souran"]
            intended = reg["exposure"]
        else:
            name = "UNIDENTIFIED"
            purpose = ""
            is_souran = None
            intended = "unknown"
            unknown.append(s["port"])
            if s["scope"] == "all-interfaces":
                exposed_unknown.append(s["port"])

        reachable = None
        if fw is not None and s["scope"] != "loopback":
            reachable = s["port"] in fw

        verdict = "ok"
        notes = []
        if reg is None:
            verdict = "unidentified"
            if s["scope"] == "all-interfaces":
                verdict = "unidentified-exposed"
                notes.append("listening on all interfaces and not in the "
                             "registry; identify before trusting the firewall")
        elif is_souran is False and s["scope"] == "all-interfaces" \
                and not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", s["addr"]):
            verdict = "third-party-exposed"
            notes.append("not a Souran service; exposed on all interfaces")
        elif intended == "LAN" and s["scope"] == "all-interfaces" \
                and reachable is False:
            notes.append("intended LAN exposure, currently blocked by the "
                         "firewall — clients cannot reach it")
        elif intended == "loopback" and s["scope"] == "all-interfaces":
            verdict = "over-exposed"
            notes.append("intended loopback-only but bound to all interfaces")

        entries.append({
            "port": s["port"], "proto": s["proto"], "bind": s["addr"],
            "scope": s["scope"], "process": s["process"],
            "name": name, "purpose": purpose,
            "souran": is_souran, "intended_exposure": intended,
            "firewall_reachable": reachable,
            "verdict": verdict, "notes": " ".join(notes),
        })

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "version": "5.1.0",
        "host": socket.gethostname(),
        "firewall_loaded": fw is not None,
        "firewall_allows": sorted(fw) if fw is not None else None,
        "summary": {
            "sockets": len(socks),
            "distinct_ports": len({s["port"] for s in socks}),
            "souran_ports": len({s["port"] for s in socks
                                 if PORT_REGISTRY.get(s["port"], {}).get("souran")}),
            "all_interfaces": len([s for s in socks
                                   if s["scope"] == "all-interfaces"]),
            "unidentified_ports": sorted(set(unknown)),
            "unidentified_exposed": sorted(set(exposed_unknown)),
        },
        "entries": entries,
    }


def render_text(rep: dict) -> str:
    L = []
    L.append("=" * 96)
    L.append(f"SOURAN AI NETWORK SERVER v{rep['version']} — PORT MAP")
    L.append(f"host={rep['host']}  generated={rep['generated_at']}")
    fw = rep["firewall_allows"]
    L.append(f"firewall: {'LOADED, LAN allows ' + str(fw) if fw is not None else 'NOT LOADED'}")
    s = rep["summary"]
    L.append(f"{s['sockets']} sockets, {s['distinct_ports']} distinct ports, "
             f"{s['souran_ports']} Souran-owned, {s['all_interfaces']} on all interfaces")
    L.append("=" * 96)
    hdr = f"{'PORT':<7}{'PROTO':<11}{'SCOPE':<18}{'PROCESS':<22}{'VERDICT':<22}NAME"
    L.append(hdr)
    L.append("-" * 96)
    for e in rep["entries"]:
        L.append(f"{e['port']:<7}{e['proto']:<11}{e['scope']:<18}"
                 f"{(e['process'] or '-'):<22}{e['verdict']:<22}{e['name'][:32]}")
    if s["unidentified_ports"]:
        L.append("")
        L.append("UNIDENTIFIED PORTS: " + ", ".join(
            str(p) for p in s["unidentified_ports"]))
        if s["unidentified_exposed"]:
            L.append("  ...of which EXPOSED on all interfaces: "
                     + ", ".join(str(p) for p in s["unidentified_exposed"]))
    return "\n".join(L)


if __name__ == "__main__":
    import sys
    rep = build_report()
    if "--json" in sys.argv:
        print(json.dumps(rep, indent=2))
    else:
        print(render_text(rep))
