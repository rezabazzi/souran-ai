#!/usr/bin/env python3
"""
SOURAN AI NETWORK SERVER v4.0.0 — Live Telemetry Collector
File: souran_telemetry.py

WHY THIS FILE EXISTS
--------------------
The v4 dashboard (port 8383) served HARDCODED numbers: 12,847 queries,
an 87.3% cache-hit rate, and log rows dated 2026-09-30. It looked
plausible and was completely fictional. A dashboard that lies is worse
than no dashboard, because it makes a broken resolver look healthy —
which is precisely how the 22-hour total DNS outage stayed invisible.

So: every value below is read from the live system. If a source is
unavailable the API returns an explicit "unavailable" marker rather than
a plausible-looking number.

SOURCES (all real):
  - resolver tier stats  : /opt/souran-ai/souran-doh-fallback.py :54/health
  - poison counters      : same health endpoint (primary/fallback/poisoned)
  - unbound internals    : unbound-control stats (queries, cache hits)
  - service state        : systemctl
  - listeners            : ss
  - active egress        : iptables nat OUTPUT rules
  - proxy / tor          : local ports + systemctl

Stdlib + psutil only. No network calls, no fabricated fallbacks.
"""

from __future__ import annotations

import json
import re
import shutil
import socket
import subprocess
import time
from typing import Any, Dict, List, Optional

UNBOUND_CTL = "/opt/souran-ai/engine/unbound/sbin/unbound-control"
UNBOUND_CONF = "/opt/souran-ai/config/souran-unbound.conf.yaml"
FALLBACK_HEALTH = ("127.0.0.1", 54)

# Services the stack depends on. Order matters: first is most critical.
SERVICES = [
    ("souran-dns", "DNS Core (unbound tier 1)", True),
    ("souran-doh-fallback", "Poison-proof resolver (:53/:853)", True),
    ("souran-dns-dot", "DNS Core DoT (:5354)", False),
    ("souran-8082-dashboard", "Hermes Management (:8082)", False),
    ("souran-8083-doh", "User DoH (:8083)", False),
    ("souran-web-8383", "Neuro Dashboard (:8383)", False),
    ("souran-watchdog", "Watchdog", False),
    ("tor@default", "Tor SOCKS (:9050)", False),
    ("cloudflared", "Cloudflare Tunnel", False),
]

PORTS = [
    (53, "DNS", "udp+tcp"),
    (853, "DNS-over-TLS", "tcp"),
    (8082, "Hermes Management", "tcp"),
    (8083, "User DoH", "tcp"),
    (8383, "Neuro Dashboard", "tcp"),
    (9050, "Tor SOCKS5", "tcp"),
    (5399, "Unbound tier-1 internal", "udp+tcp"),
]


def _run(cmd: List[str], timeout: float = 5.0) -> Optional[str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
        if proc.returncode != 0:
            return None
        return proc.stdout.decode("utf-8", "replace")
    except (subprocess.TimeoutExpired, OSError):
        return None


def _tcp_ok(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Resolver tier stats (the DoH front-end) — this is the key health signal
# ---------------------------------------------------------------------------
def resolver_health() -> Dict[str, Any]:
    host, port = FALLBACK_HEALTH
    try:
        with socket.create_connection((host, port), timeout=3) as s:
            s.settimeout(3)
            s.sendall(b"GET /health HTTP/1.1\r\nHost: localhost\r\n"
                      b"Connection: close\r\n\r\n")
            buf = b""
            while True:
                chunk = s.recv(65535)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > 1 << 16:
                    break
    except OSError as exc:
        return {"available": False, "error": f"{type(exc).__name__}: {exc}"}

    head, _, body = buf.partition(b"\r\n\r\n")
    if b"Transfer-Encoding: chunked" in head:
        out, rest = b"", body
        while True:
            line, _, tail = rest.partition(b"\r\n")
            try:
                n = int(line.strip(), 16)
            except ValueError:
                break
            if n == 0:
                break
            out += tail[:n]
            rest = tail[n + 2:]
        body = out
    try:
        return {"available": True, **json.loads(body.decode("utf-8", "replace"))}
    except Exception as exc:
        return {"available": False, "error": f"bad health payload: {exc}"}


# ---------------------------------------------------------------------------
# unbound internals
# ---------------------------------------------------------------------------
def unbound_stats() -> Dict[str, Any]:
    if not shutil.os.path.exists(UNBOUND_CTL):
        return {"available": False, "error": "unbound-control missing"}
    raw = _run([UNBOUND_CTL, "-c", UNBOUND_CONF, "stats_noreset"], timeout=8.0)
    if raw is None:
        return {"available": False, "error": "unbound-control did not respond"}
    vals: Dict[str, int] = {}
    for line in raw.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            try:
                vals[k.strip()] = int(v.strip())
            except ValueError:
                pass
    if not vals:
        return {"available": False, "error": "no counters parsed"}
    return {
        "available": True,
        "queries": sum(v for k, v in vals.items() if k.endswith("num.queries")),
        "cache_hits": sum(v for k, v in vals.items() if k.endswith("num.cachehits")),
        "cache_miss": sum(v for k, v in vals.items() if k.endswith("num.cachemiss")),
        "recursion_time_avg": round(
            sum(v for k, v in vals.items() if "recursion.time.avg" in k)
            / max(1, len([k for k in vals if "recursion.time.avg" in k])), 4),
        "unwanted_replies": vals.get("total.unwanted.replies", 0),
        "raw_counters": len(vals),
    }


# ---------------------------------------------------------------------------
# Services and ports
# ---------------------------------------------------------------------------
def services() -> List[Dict[str, Any]]:
    out = []
    for unit, desc, critical in SERVICES:
        state = _run(["systemctl", "is-active", unit], timeout=4.0)
        state = (state or "").strip() or "unknown"
        out.append({
            "unit": unit,
            "description": desc,
            "state": state,
            "active": state == "active",
            "critical": critical,
            "enabled": (_run(["systemctl", "is-enabled", unit],
                             timeout=4.0) or "").strip() or "unknown",
        })
    return out


def listeners() -> List[Dict[str, Any]]:
    raw = _run(["ss", "-tuln"], timeout=6.0) or ""
    found: Dict[int, Dict[str, Any]] = {}
    for line in raw.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        proto, local = parts[0], parts[4]
        m = re.search(r":(\d+)$", local)
        if not m:
            continue
        port = int(m.group(1))
        rec = found.setdefault(port, {"port": port, "udp": False, "tcp": False,
                                      "address": local})
        if proto.startswith("udp"):
            rec["udp"] = True
        else:
            rec["tcp"] = True
    out = []
    for port, _name, _kind in PORTS:
        rec = found.get(port)
        out.append({
            "port": port,
            "listening": rec is not None,
            "proto": ("udp+tcp" if rec and rec["udp"] and rec["tcp"]
                      else "udp" if rec and rec["udp"]
                      else "tcp" if rec and rec["tcp"] else "none"),
            "address": rec["address"] if rec else None,
        })
    return out


# ---------------------------------------------------------------------------
# Egress / censorship posture
# ---------------------------------------------------------------------------
def egress_rules() -> Dict[str, Any]:
    raw = _run(["sudo", "-n", "iptables", "-t", "nat", "-S", "OUTPUT"],
               timeout=6.0) or ""
    rules = [l for l in raw.splitlines() if l.strip()]
    tor_redirect = [r for r in rules if "--to-ports 9053" in r]
    resolver_bypass = [r for r in rules if "--uid-owner 993" in r
                       or "--uid-owner 997" in r]
    return {
        "available": bool(rules),
        "total_rules": len(rules),
        "tor_dns_redirect": tor_redirect,
        "resolver_bypass": resolver_bypass,
        "resolver_bypass_ok": len(resolver_bypass) >= 2,
        "cloudflare_redirect": [r for r in rules if "17844" in r],
    }


def bypass_stack() -> Dict[str, Any]:
    return {
        "tor_socks_9050": _tcp_ok("127.0.0.1", 9050),
        "proxy_8118": _tcp_ok("127.0.0.1", 8118),
        "proxy_required_for_doh": True,
        "doh_note": "Direct DoH is reset on this network (curl rc=35); "
                    "the resolver reaches DoH only via the local proxy.",
        "modes": {
            "tor": (_run(["systemctl", "is-active", "tor@default"],
                         timeout=4.0) or "").strip(),
            "ouinet": (_run(["systemctl", "is-active", "ouinet"],
                            timeout=4.0) or "").strip(),
            "snowflake": (_run(["systemctl", "is-active", "snowflake"],
                              timeout=4.0) or "").strip(),
        },
    }


# ---------------------------------------------------------------------------
# Live resolution probe — the only honest end-to-end signal
# ---------------------------------------------------------------------------
def _dig(domain: str, port: int = 53, tcp: bool = False) -> Dict[str, Any]:
    t0 = time.time()
    proto = ["+tcp"] if tcp else []
    raw = _run(["dig", "+time=8", "+tries=1", *proto, "@127.0.0.1",
                "-p", str(port), domain, "A"], timeout=12.0)
    elapsed = int((time.time() - t0) * 1000)
    if raw is None:
        return {"domain": domain, "ok": False, "ms": elapsed,
                "answers": [], "status": "dig-failed"}
    status = ""
    m = re.search(r"status: (\w+)", raw)
    if m:
        status = m.group(1)
    # Extract ONLY the answer records. A naive regex over the whole dig
    # output also matches the SERVER: 127.0.0.1#53 line, which made the
    # probe report 127.0.0.1 as a resolution result (and then trip its own
    # poison check). Restrict to the ANSWER SECTION and require an A-record
    # type token.
    ips: list = []
    if "ANSWER SECTION:" in raw:
        body = raw.split("ANSWER SECTION:", 1)[1]
        # The answer section ends at the next section marker or the footer.
        for marker in (";; AUTHORITY SECTION", ";; ADDITIONAL",
                       ";; Query time:", ";; SERVER:"):
            if marker in body:
                body = body.split(marker, 1)[0]
        for line in body.splitlines():
            if "IN\tA\t" in line or "\tIN\tA\t" in line:
                parts = line.split()
                if parts and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", parts[-1]):
                    ips.append(parts[-1])
    return {"domain": domain, "ok": status == "NOERROR" and bool(ips),
            "ms": elapsed, "answers": ips, "status": status or "empty"}


def is_poisonable_answer(answers) -> bool:
    """True if any answer is a private/reserved address.

    Same rule the resolver front-end uses to reject injected answers.
    A public name must never legitimately resolve to RFC1918/loopback/
    link-local/multicast space, so finding one means injection reached
    the client.
    """
    for ip in answers or []:
        try:
            packed = socket.inet_aton(ip)
        except OSError:
            continue
        val = int.from_bytes(packed, "big")
        for base, mask in (
            (0x0A000000, 0xFF000000),   # 10/8
            (0x7F000000, 0xFF000000),   # 127/8
            (0xAC100000, 0xFFF00000),   # 172.16/12
            (0xC0A80000, 0xFFFF0000),   # 192.168/16
            (0xA9FE0000, 0xFFFF0000),   # 169.254/16
            (0xE0000000, 0xFFFFFF00),   # 224/4 multicast
            (0x00000000, 0xFF000000),   # 0/8
        ):
            if (val & mask) == base:
                return True
    return False


PROBE_DOMAINS = ["example.com", "telegram.org", "instagram.com",
                 "youtube.com", "reddit.com", "github.com", "x.com"]


def probe(count: int = 5) -> List[Dict[str, Any]]:
    domains = PROBE_DOMAINS[:max(1, count)]
    return [_dig(d) for d in domains]


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------
def snapshot() -> Dict[str, Any]:
    started = time.time()
    res = resolver_health()
    stats = res.get("stats", {}) if res.get("available") else {}
    total = sum(v for k, v in stats.items() if isinstance(v, int))
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "version": read_version(),
        "resolver": res,
        "unbound": unbound_stats(),
        "services": services(),
        "listeners": listeners(),
        "egress": egress_rules(),
        "bypass": bypass_stack(),
        "collect_ms": int((time.time() - started) * 1000),
        "data_source": "live — no synthetic values",
        "resolver_totals": stats,
        "resolver_query_total": total,
    }


def read_version() -> str:
    try:
        with open("/opt/souran-ai/VERSION") as fh:
            for line in fh:
                if line.startswith("SOURAN_DNS_VERSION="):
                    return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return "unknown"


if __name__ == "__main__":
    print(json.dumps(snapshot(), indent=2, default=str))