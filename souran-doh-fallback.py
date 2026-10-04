#!/usr/bin/env python3
"""
SOURAN AI NETWORK SERVER v4.0.0 — DoH Fallback Resolver Tier
File: souran-doh-fallback.py   |  Port: 8384 (internal front-end)

PURPOSE
-------
On the Iran network profile, plain UDP/53 responses from authoritative
servers are actively forged. Observed live:

    telegram.org -> 10.10.34.36   (private, unroutable; real = 149.154.167.99)
    instagram.com -> 10.10.34.36  (real = 57.144.244.34)

Direct TCP to the genuine gTLD servers returns EMPTY, flag-less
answers, so unbound cannot be rescued by forcing TCP upstream.

Measured reachability from this host:
    TCP/853 outbound  -> BLOCKED  (DoT impossible)
    HTTPS/443 outbound-> OPEN     (DoH clean and authoritative)
    UDP/53            -> FORGED

Therefore DoH over 443 is the only trustworthy upstream transport here.

This tier is a RESOLVER FRONT-END, not a bypass of policy: clients still
point at the local unbound. It only intervenes when unbound's iterative
answer is missing or demonstrably untrustworthy (RFC1918/loopback/link-
local answers for public names are the signature of this censor's
injection). A fallback is used ONLY when the primary result fails those
checks, so zero-upstream resolution remains the normal path.

Dependencies: Python standard library only (wire-format DNS is built
by hand so this runs on any host with no pip install).
"""

import base64
import json
import os
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
from urllib.parse import urlparse

# v4.3: general RR-type resolution. v4.2.1 could only handle A/AAAA, which
# made MX/TXT/CNAME/SRV/SVCB time out or return a malformed packet. This
# module preserves upstream rdata verbatim so every record type survives.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from souran_dns_rr import (  # noqa: E402
        ADDRESS_TYPES,
        answer_addresses,
        build_nodata,
        build_passthrough,
        has_answer_of_type,
        iter_answers,
        question_type,
    )
    _RR_OK = True
except Exception as _rr_exc:  # pragma: no cover - fail loud, not silent
    _RR_OK = False
    _RR_ERR = _rr_exc
    print(f"[souran-doh-fallback] FATAL: souran_dns_rr import failed: {_rr_exc}",
          file=sys.stderr, flush=True)
    raise

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
# Primary (tier 1): local unbound, true zero-upstream iterative resolver.
# Defaults to the internal port because this front-end owns :53 for the LAN.
UPSTREAM_BIND = (
    os.environ.get("SOURAN_PRIMARY_HOST", "127.0.0.1"),
    int(os.environ.get("SOURAN_PRIMARY_PORT", "5353")),
)
FALLBACK_HOST = os.environ.get("SOURAN_DOH_HOST", "cloudflare-dns.com")
FALLBACK_URL = os.environ.get(
    "SOURAN_DOH_URL", "https://cloudflare-dns.com/dns-query"
)
SECONDARY_URL = os.environ.get(
    "SOURAN_DOH_URL2", "https://dns.google/resolve"
)
LISTEN_HOST = os.environ.get("SOURAN_LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("SOURAN_LISTEN_PORT", "8384"))
if len(sys.argv) > 1:
    LISTEN_PORT = int(sys.argv[1])
# Answer clients over UDP too: LAN stub resolvers overwhelmingly use UDP.
LISTEN_UDP = os.environ.get("SOURAN_LISTEN_UDP", "1") != "0"

CACHE_MAX = 4096
_cache = {}
_cache_lock = threading.Lock()

STATS = {"primary": 0, "fallback": 0, "poisoned": 0, "fail": 0}

# --------------------------------------------------------------------------
# BOOTSTRAP — breaks the circular dependency.
#
# The DoH hostnames must be resolved before DoH can be used, but on this
# network their own DNS answers are poisoned (cloudflare-dns.com resolved
# to 2001:4188:2:600:10:10:34:36). So we pin the bootstrap IPs here and
# connect to the IP while still doing full TLS verification against the
# hostname (SNI + cert chain), which keeps the trust guarantee intact.
#
# These are stable, published anycast endpoints:
#   cloudflare-dns.com -> 104.16.248.249 / 104.16.249.249 (1.1.1.1 also valid)
#   dns.google          -> 8.8.8.8 / 8.8.4.4
# --------------------------------------------------------------------------
BOOTSTRAP = {
    "cloudflare-dns.com": ["104.16.248.249", "104.16.249.249", "1.1.1.1", "1.0.0.1"],
    "dns.google": ["8.8.8.8", "8.8.4.4"],
}
# --------------------------------------------------------------------------
# EGRESS — DoH MUST go through the local censorship-bypass proxy.
#
# Measured on this host: a direct TLS connection to a DoH endpoint is
# reset (curl rc=35), while the same request through the local proxy
# (127.0.0.1:8118) succeeds. So DoH reachability depends on that proxy
# being up. We therefore pin it here rather than relying on inherited
# environment variables, which systemd units do not always carry.
#
# If the proxy is down we fail loudly instead of silently degrading to a
# direct (blocked) connection.
# --------------------------------------------------------------------------
PROXY = os.environ.get("SOURAN_PROXY", "http://127.0.0.1:8118")


def proxy_is_up() -> bool:
    if not PROXY:
        return True
    try:
        u = urlparse(PROXY)
        s = socket.create_connection((u.hostname or "127.0.0.1",
                                      u.port or 8080), timeout=2)
        s.close()
        return True
    except OSError:
        return False


# Round-robin cursor so we do not hammer one anycast IP.
_rr = {"n": 0}
_rr_lock = threading.Lock()

# Single-flight + short negative cache.
#
# A DoH round-trip costs ~2-3 s on this link. Without single-flight, ten
# clients asking for the same censored name each pay that cost and can
# exceed their own timeout. One thread performs the lookup; the rest
# wait on the same result. Negative results are cached briefly so a
# hard-failing name cannot become a 2-3 s stall per query.
_inflight = {}
_inflight_lock = threading.Lock()
_negcache = {}
NEG_TTL = 5.0

# Ranges that must never be a legitimate answer for a public name on a
# global recursive resolver. Seeing these == upstream injection.
POISON_NETS = [
    (0x0A000000, 0xFF000000),   # 10.0.0.0/8
    (0x7F000000, 0xFF000000),   # 127.0.0.0/8
    (0xAC100000, 0xFFF00000),   # 172.16.0.0/12
    (0xC0A80000, 0xFFFF0000),   # 192.168.0.0/16
    (0xA9FE0000, 0xFFFF0000),   # 169.254.0.0/16
    (0xE0000000, 0xFFFFFF00),   # 224.0.0.0/24 multicast
]


def is_poison(ip: str) -> bool:
    """True if a public name resolved to a private/reserved address."""
    try:
        packed = socket.inet_aton(ip)
    except OSError:
        return False
    val = struct.unpack("!I", packed)[0]
    return any((val & mask) == base for base, mask in POISON_NETS)


# --------------------------------------------------------------------------
# Minimal DNS wire format (we only need build/parse for A/AAAA + passthrough)
# --------------------------------------------------------------------------
def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        raw = label.encode("idna" if any(ord(c) > 127 for c in label) else "ascii")
        if len(raw) > 63:
            raise ValueError("label too long")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _decode_name(data: bytes, offset: int):
    labels = []
    jumped = False
    end = offset
    hops = 0
    while True:
        if offset >= len(data):
            return None, end
        ln = data[offset]
        if ln == 0:
            offset += 1
            if not jumped:
                end = offset
            break
        if ln & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                return None, end
            ptr = ((ln & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            offset = ptr
            jumped = True
            hops += 1
            if hops > 32:
                return None, end
            continue
        offset += 1
        if offset + ln > len(data):
            return None, end
        labels.append(data[offset:offset + ln])
        offset += ln
        if not jumped:
            end = offset
    try:
        return ".".join(l.decode("ascii", "replace") for l in labels) + ".", end
    except Exception:
        return None, end


def build_query(qname: str, qtype: int = 1, qid: int = 0x5355) -> bytes:
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # RD=1
    return header + _encode_name(qname) + struct.pack("!HH", qtype, 1)


def parse_a_records(payload: bytes):
    """Return list of A/AAAA addresses plus the rcode.

    v4.3: delegates to the general RR layer. Raises ValueError on a malformed
    packet instead of silently returning a partial answer (the old version
    broke out of the loop and served whatever it had).
    """
    return answer_addresses(payload)


def build_answer(qname: str, qtype: int, ips, _qid: int = 0, ttl: int = 300) -> bytes:
    """Construct a NOERROR response carrying the given A/AAAA records."""
    qname_enc = _encode_name(qname)
    qtype_end = qname_enc + struct.pack("!HH", qtype, 1)
    answers = b""
    count = 0
    for ip in ips:
        try:
            if qtype == 1:
                rdata = socket.inet_aton(ip)
            elif qtype == 28:
                rdata = socket.inet_pton(socket.AF_INET6, ip)
            else:
                continue
        except OSError:
            continue
        answers += qname_enc + struct.pack("!HHIH", qtype, 1, ttl, len(rdata)) + rdata
        count += 1
    header = struct.pack("!HHHHHH", _qid, 0x8180, 1, count, 0, 0)  # QR RD RA
    return header + qtype_end + answers


# --------------------------------------------------------------------------
# Upstream: primary (unbound) then DoH fallback
# --------------------------------------------------------------------------
def ask_unbound(qname: str, qtype: int = 1, timeout: float = 5.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(build_query(qname, qtype), UPSTREAM_BIND)
            data, _ = s.recvfrom(65535)
        return data
    except (socket.timeout, OSError):
        return None


_doh_gate = threading.Lock()
_doh_last = [0.0]
# Minimum spacing between DoH calls. Measured: repeated DoH handshakes in
# a burst are reset by the TLS filter (curl rc=35), while calls spaced ~1 s
# apart succeed in ~0.7 s. We serialise and pace DoH access globally.
DOH_MIN_INTERVAL = float(os.environ.get("SOURAN_DOH_INTERVAL", "0.9"))


def _doh_throttle():
    """Serialise + space out DoH calls across all threads."""
    with _doh_gate:
        now = time.time()
        wait = _doh_last[0] + DOH_MIN_INTERVAL - now
        if wait > 0:
            time.sleep(wait)
        _doh_last[0] = time.time()


def _doh_json(url: str, qname: str, qtype: int, timeout: float = 8.0):
    """Fetch a DoH JSON document. Shared by _doh_get and _doh_rdata.

    Two network realities force this design:
      1. Resolving the DoH hostname over DNS returns a poisoned address,
         so we connect to pinned bootstrap IPs (BOOTSTRAP) and rely on
         TLS SNI/cert verification for authenticity.
      2. Python's own TLS ClientHello (JA3) is reset on DoH endpoints
         while OpenSSL/curl connect fine -- confirmed by measurement:
         openssl s_client OK, curl OK, python ssl FAIL (ECONNRESET).
         We therefore shell out to curl, whose TLS fingerprint is not
         what the filter blocks.

    A DoH round-trip on this link costs ~2-3 s, so `timeout` is the
    per-attempt budget and the caller must allow for one attempt per
    upstream plus process spawn overhead.
    """
    host = urlparse(url).netloc
    path = urlparse(url).path.rstrip("/") or "/dns-query"
    # v4.3: full qtype->mnemonic map. The old default of "A" meant an SVCB,
    # HTTPS, DS or DNSKEY query was silently rewritten to an A query upstream,
    # so those types could never resolve. RFC 3597 TYPE#### is the correct
    # fallback for anything unknown.
    qt = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 2: "NS", 12: "PTR",
          16: "TXT", 33: "SRV", 6: "SOA", 257: "CAA", 64: "SVCB",
          65: "HTTPS", 43: "DS", 48: "DNSKEY", 47: "NSEC", 46: "RRSIG",
          50: "NSEC3", 51: "NSEC3PARAM", 99: "SPF", 35: "NAPTR",
          39: "DNAME", 52: "TLSA", 59: "CDS", 60: "CDNSKEY",
          62: "CSYNC", 249: "TKEY", 250: "TSIG", 255: "ANY",
          256: "URI", 61: "OPENPGPKEY", 53: "SMIMEA"}.get(qtype, f"TYPE{qtype}")
    target = f"{path}?name={qname}&type={qt}"

    ips = BOOTSTRAP.get(host)
    cmd_base = ["curl", "-s", "--max-time", str(int(timeout)),
                "-H", "accept: application/dns-json"]
    if PROXY:
        # Route through the bypass proxy and clear conflicting inherited
        # settings so the request cannot silently go out direct.
        cmd_base += ["--proxy", PROXY, "-q"]
    else:
        cmd_base += ["-q"]

    attempts = []
    if ips:
        with _rr_lock:
            _rr["n"] = (_rr["n"] + 1) % len(ips)
            st = _rr["n"]
        ordered = ips[st:] + ips[:st]
        for ip in ordered:
            # --resolve pins the IP while keeping SNI + cert check on host
            attempts.append(cmd_base + ["--resolve", f"{host}:443:{ip}",
                                        f"https://{host}{target}"])
    else:
        attempts.append(cmd_base + [f"https://{host}{target}"])

    # Bounded by an overall deadline, not by attempt count.
    #
    # Measured behaviour of this link: DoH round-trips cost ~0.7-2.5 s and
    # the TLS filter rejects bursts (curl rc=35), so calls are paced by
    # _doh_throttle() and retried across all bootstrap IPs until the
    # deadline. Retrying blindly without a budget once took 12 s and made
    # the client give up even though DoH was reachable.
    # v4.3.2: the default was 12 s, but a single DoH round-trip costs
    # 2.0-2.7 s here and _doh_throttle() spaces calls 0.9 s apart, so only
    # ~3 attempts fit and the 4th is cut off mid-flight (curl rc=28). Under
    # concurrent load that produced SERVFAIL for valid names. The unit sets
    # SOURAN_DOH_BUDGET=20; this default keeps the module correct standalone.
    deadline = time.time() + float(os.environ.get("SOURAN_DOH_BUDGET", "20"))
    last_rc = None
    blob_out = None

    while time.time() < deadline:
        for cmd in attempts:
            if time.time() >= deadline:
                break
            _doh_throttle()
            remaining = max(1.0, deadline - time.time())
            child_env = dict(os.environ)
            if PROXY:
                # --proxy is on the command line; setting proxy env vars
                # causes curl to double-proxy and hang (rc=28 timeout).
                # Clear them so only the explicit --proxy is used.
                child_env.pop("http_proxy", None)
                child_env.pop("https_proxy", None)
                child_env.pop("HTTP_PROXY", None)
                child_env.pop("HTTPS_PROXY", None)
            try:
                proc = subprocess.run(cmd, capture_output=True,
                                      timeout=min(remaining, timeout + 2),
                                      env=child_env)
            except (subprocess.TimeoutExpired, OSError):
                continue
            last_rc = proc.returncode
            if proc.returncode != 0 or not proc.stdout:
                continue
            blob_out = proc.stdout
            break
        if blob_out:
            break

    if not blob_out:
        print(f"[souran-doh-fallback] DoH {host} gave up "
              f"(last curl rc={last_rc})", file=sys.stderr, flush=True)
        return None

    try:
        doc = json.loads(blob_out.decode("utf-8", "replace"))
    except Exception:
        return None
    if doc.get("Status") not in (0, 3):
        # 1 = FORMERR, 2 = SERVFAIL ... genuine upstream failure.
        return None
    return doc


def _doh_is_nodata(doc) -> bool:
    """True when DoH answered NOERROR but the name has no record of this type.

    A NODATA answer is a VALID, authoritative result (the zone exists, the
    requested type does not) and must not be treated as a lookup failure.
    v4.3.2 conflated it with failure: `_doh_get` returned None for an empty
    Answer list, so _resolve_uncached fell through to its final
    `return payload if payload else None`, which handed the client tier 1's
    SERVFAIL packet. Measured: race0.example.org returns SERVFAIL locally while
    the authoritative DoH answer is Status 0 with an SOA in Authority.
    """
    return bool(doc) and doc.get("Status") == 0 and not (doc.get("Answer") or [])


def _doh_get(url: str, qname: str, qtype: int, timeout: float = 8.0):
    """A/AAAA addresses only (legacy path kept for compatibility)."""
    doc = _doh_json(url, qname, qtype, timeout)
    if not doc:
        return None
    ips_out = []
    for ans in doc.get("Answer") or []:
        if ans.get("type") not in (1, 28):
            continue
        for part in (ans.get("data") or "").split("\n"):
            part = part.strip()
            if not part:
                continue
            try:
                if ans.get("type") == 1:
                    socket.inet_aton(part)
                else:
                    socket.inet_pton(socket.AF_INET6, part)
                ips_out.append(part)
            except OSError:
                continue
    return ips_out or None


def _doh_rdata(url: str, qname: str, qtype: int, timeout: float = 8.0):
    """Fetch ANY record type from a DoH JSON endpoint as (rtype, rdata, ttl).

    v4.3: `_doh_get` only understands A/AAAA, so a poisoned A answer forced
    Tier 2 to give up on MX/TXT/CNAME/SRV entirely. This returns wire-format
    rdata for the requested type so `build_passthrough` can emit it verbatim.

    rdata is encoded per RFC 1035 (length-prefixed labels / character-strings)
    rather than guessed, and an unencodable answer is skipped instead of
    producing malformed bytes.
    """
    doc = _doh_json(url, qname, qtype, timeout)
    if not doc or doc.get("Status") != 0:
        return None
    out = []
    for ans in doc.get("Answer") or []:
        if ans.get("type") != qtype:
            continue
        data = (ans.get("data") or "").strip()
        if not data:
            continue
        rd = _rdata_from_text(qtype, data)
        if rd is None:
            continue
        try:
            ttl = int(ans.get("TTL") or 300)
        except (TypeError, ValueError):
            ttl = 300
        out.append((qtype, rd, ttl))
    return out or None


def _rdata_from_text(qtype: int, data: str):
    """Encode a DoH JSON 'data' string into wire rdata for `qtype`."""
    try:
        if qtype == 1:
            return socket.inet_aton(data)
        if qtype == 28:
            return socket.inet_pton(socket.AF_INET6, data)
        if qtype in (2, 5, 12):                      # NS / CNAME / PTR
            return _encode_name(data.rstrip("."))
        if qtype == 15:                             # MX: pref + exchange
            parts = data.split()
            if len(parts) != 2:
                return None
            return struct.pack("!H", int(parts[0])) + _encode_name(parts[1].rstrip("."))
        if qtype == 6:                              # SOA: mname rname serial...
            parts = data.split()
            if len(parts) < 7:
                return None
            return (_encode_name(parts[0].rstrip("."))
                    + _encode_name(parts[1].rstrip("."))
                    + struct.pack("!IIIII", int(parts[2]), int(parts[3]),
                                  int(parts[4]), int(parts[5]), int(parts[6])))
        if qtype == 16:                             # TXT: char-strings
            raw = b""
            for chunk in _split_dns_strings(data):
                enc = chunk.encode("utf-8", "replace")
                if len(enc) > 255:
                    enc = enc[:255]
                raw += bytes([len(enc)]) + enc
            return raw or None
        if qtype == 33:                             # SRV
            parts = data.split()
            if len(parts) != 4:
                return None
            return struct.pack("!HHH", int(parts[0]), int(parts[1]), int(parts[2])) \
                + _encode_name(parts[3].rstrip("."))
        if qtype in (64, 65):
            # SVCB/HTTPS rdata is NOT a bare name: it is
            #   priority(uint16) target(name) params(...)
            # and `data` here is just the target name, so emit a minimal
            # ServiceMode presentation with priority 1 and no params.
            # v4.3 returned `_encode_name(data)` alone, which produced a
            # packet whose first two bytes were the length of the first
            # label — structurally wrong even though it sometimes parsed.
            return struct.pack("!H", 1) + _encode_name(data.rstrip("."))
    except (ValueError, struct.error, OSError):
        return None
    return None


def _split_dns_strings(data: str):
    """Split a DoH TXT 'data' value into its constituent strings.

    DoH JSON returns TXT as one or more quoted strings, e.g.
    `"v=spf1 include:_spf.google.com ~all"` or `"a" "b"`. Re-join them so
    segment boundaries are rebuilt correctly (a >255-byte TXT must be
    split into 255-byte character-strings).
    """
    import re as _re
    parts = _re.findall(r'"((?:[^"\\]|\\.)*)"', data)
    if parts:
        return [_unescape_dns_string(p) for p in parts]
    return [data]


def _unescape_dns_string(s: str) -> str:
    out, i = [], 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            out.append(s[i + 1])
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)



def _cache_get(key):
    with _cache_lock:
        hit = _cache.get(key)
        if hit and hit[0] > time.time():
            return hit[1]
        _cache.pop(key, None)
    return None


def _cache_put(key, value, ttl=300):
    with _cache_lock:
        if len(_cache) > CACHE_MAX:
            for k in [k for k, v in _cache.items() if v[0] <= time.time()][:512]:
                _cache.pop(k, None)
        _cache[key] = (time.time() + ttl, value)


def _resolve_uncached(qname: str, qtype: int):
    """Tier 1 then Tier 2, no locking."""
    # ---- Tier 1: local unbound (true zero-upstream iterative) ----------
    payload = ask_unbound(qname, qtype)
    if payload:
        try:
            ips, rcode = answer_addresses(payload)
        except ValueError as exc:
            # Malformed upstream packet: never serve invented/partial bytes.
            STATS["malformed"] = STATS.get("malformed", 0) + 1
            print(f"[souran-doh-fallback] malformed tier-1 packet for "
                  f"{qname}/{qtype}: {exc}", flush=True)
            payload = None
            ips, rcode = [], 2
        else:
            # v4.3: a NODATA/NXDOMAIN answer must NOT count as a usable
            # result just because it carries no addresses. Only accept it
            # when the answer section actually holds the requested type
            # (or genuinely holds no RRs at all = valid NODATA). Without
            # this, an empty A answer masked a working MX/TXT answer and the
            # client got a bogus empty reply.
            if rcode == 0:
                has_rrs = any(True for _r, _d, _t in iter_answers(payload))
                useful = has_answer_of_type(payload, qtype)
                poisoned = bool(ips) and any(is_poison(ip) for ip in ips)
                if useful and not poisoned:
                    STATS["primary"] += 1
                    _cache_put((qname.lower(), qtype), payload, 300)
                    return payload, False
                if poisoned:
                    STATS["poisoned"] += 1   # never cache or serve an injected answer
                elif has_rrs:
                    # Answer holds RRs, just not the requested type. That is a
                    # real NODATA/CNAME-chain situation — trust it (e.g. a
                    # CNAME-only answer for a query the client will follow).
                    STATS["primary"] += 1
                    _cache_put((qname.lower(), qtype), payload, 300)
                    return payload, False
                else:
                    # Tier 1 answered NOERROR with an EMPTY answer section.
                    #
                    # unbound does this for a name whose NS/TXT it could not
                    # complete on this DPI'd link (observed: google.com NS/TXT
                    # return 0 RRs instantly while DoH returns the real
                    # records). Trusting that empty reply hides data that IS
                    # available, so fall through to the encrypted tier instead
                    # of serving a hollow answer.
                    STATS["nodata"] = STATS.get("nodata", 0) + 1
            elif rcode == 3:
                # Genuine NXDOMAIN — authoritative, serve as-is (negative cache).
                STATS["primary"] += 1
                _cache_put((qname.lower(), qtype), payload, 60)
                return payload, False
            else:
                # SERVFAIL / REFUSED / NOTIMPL from tier 1 is NOT an answer.
                # v4.2.1 fell through to the `else` branch and cached it for
                # 60 s, so a tier-1 failure (e.g. unbound cannot complete SOA
                # on this DPI'd link) was served as if authoritative. Never
                # cache or return a non-authoritative rcode — escalate to DoH.
                STATS["servfail"] = STATS.get("servfail", 0) + 1
                print(f"[souran-doh-fallback] tier-1 rcode={rcode} for "
                      f"{qname}/{qtype} — escalating to DoH", flush=True)
                payload = None

    # ---- Tier 2: DoH over HTTPS/443 (only trustworthy transport here) -
    for url in (FALLBACK_URL, SECONDARY_URL):
        # v4.3: address types take the poison-checked fast path; every other
        # type goes through verbatim rdata so MX/TXT/CNAME/SRV/SVCB work.
        if qtype in ADDRESS_TYPES:
            ips = _doh_get(url, qname, qtype)
            if ips and not any(is_poison(ip) for ip in ips):
                STATS["fallback"] += 1
                # Build a REAL answer from the clean DoH result. Returning the
                # upstream unbound payload here would re-serve the injected
                # private address we just rejected.
                good = build_answer(qname, qtype, ips, _qid=0)
                _cache_put((qname.lower(), qtype), good, 120)
                return good, True
        else:
            rrs = _doh_rdata(url, qname, qtype)
            if rrs:
                STATS["fallback"] += 1
                good = build_passthrough(qname, qtype, rrs)
                _cache_put((qname.lower(), qtype), good, 120)
                return good, True

        # v4.3.2: DoH answered, but with no record of the requested type. That
        # is an authoritative NODATA, not a failure — and answering it correctly
        # is what stops tier 1's SERVFAIL from leaking to the client.
        _doc = _doh_json(url, qname, qtype)
        if _doh_is_nodata(_doc):
            STATS["nodata"] = STATS.get("nodata", 0) + 1
            good = build_nodata(qname, qtype)
            _cache_put((qname.lower(), qtype), good, 120)
            return good, True

    STATS["fail"] += 1
    return payload if payload else None, False


def resolve(qname: str, qtype: int = 1):
    """Return (response_bytes, used_fallback)."""
    key = (qname.lower(), qtype)

    cached = _cache_get(key)
    if cached:
        return cached, False

    # Brief negative cache: a name that just failed end-to-end should not
    # immediately burn another ~5 s of DoH budget for the next client.
    with _inflight_lock:
        neg = _negcache.get(key)
    if neg and neg > time.time():
        return None, False

    # Single-flight: one thread resolves, the rest wait for its result.
    with _inflight_lock:
        ev = _inflight.get(key)
        leader = ev is None
        if leader:
            ev = threading.Event()
            _inflight[key] = ev

    if not leader:
        # v4.3.2: the follower waited a flat 12 s while the leader's DoH budget
        # was ALSO 12 s. A cold lookup costs 2.0-2.7 s per DoH attempt (measured
        # on this link), so under load the leader exhausts its budget at almost
        # exactly the moment followers time out — every thread then reported
        # failure and the client saw SERVFAIL even though DoH was reachable.
        # Followers must wait longer than the leader's worst case.
        wait_s = float(os.environ.get("SOURAN_DOH_BUDGET", "12")) + 10.0
        ev.wait(timeout=wait_s)
        got = _cache_get(key)
        if got:
            return got, True
        return None, False

    try:
        result = _resolve_uncached(qname, qtype)
        if not result[0]:
            with _inflight_lock:
                _negcache[key] = time.time() + NEG_TTL
        return result
    finally:
        with _inflight_lock:
            _inflight.pop(key, None)
        ev.set()


# --------------------------------------------------------------------------
# TCP front-end speaking DNS to local clients
# --------------------------------------------------------------------------
def _edns_bufsize(data: bytes) -> int:
    """Return the UDP payload size the client advertised via EDNS0, else 0.

    The size lives in the CLASS field of the OPT pseudo-RR (type 41) in the
    additional section, not in the header's NSCOUNT/ARCOUNT. Reading it from
    the header made a normal EDNS query look like it advertised a 1-byte
    buffer, which forced needless truncation.
    """
    try:
        if len(data) < 12:
            return 0
        arcount = struct.unpack("!H", data[10:12])[0]
        off = 12
        qd = struct.unpack("!H", data[4:6])[0]
        for _ in range(qd):
            while True:
                ln = data[off]
                if ln == 0:
                    off += 1
                    break
                if ln & 0xC0 == 0xC0:
                    off += 2
                    break
                off += 1 + ln
            off += 4  # QTYPE + QCLASS
        for _ in range(arcount):
            while True:
                ln = data[off]
                if ln == 0:
                    off += 1
                    break
                if ln & 0xC0 == 0xC0:
                    off += 2
                    break
                off += 1 + ln
            rtype, rclass, _ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
            off += 10
            if rtype == 41:  # OPT
                size = rclass & 0xFFFF
                return size if 512 <= size <= 4096 else 0
            off += rdlen
    except (struct.error, IndexError):
        return 0
    return 0


def _question_end(data: bytes) -> int:
    """Offset just past the question section (used to echo it back verbatim).

    Slicing the echo as ``12 + len(qname) + 5`` is wrong: an encoded name is
    ``sum(1 + len(label)) + 1`` bytes because every label carries a length byte
    and the name ends with a root zero byte, and the question then needs 4 more
    bytes for QTYPE and QCLASS. For ``cloudflare.com`` that is 20 bytes, not 19
    — the old slice truncated the QCLASS and clients rejected the message with
    "malformed message packet".
    """
    try:
        qd = struct.unpack("!H", data[4:6])[0]
        off = 12
        for _ in range(qd):
            while True:
                ln = data[off]
                if ln == 0:
                    off += 1
                    break
                if ln & 0xC0 == 0xC0:
                    off += 2
                    break
                off += 1 + ln
            off += 4  # QTYPE + QCLASS
        return off
    except (struct.error, IndexError):
        return len(data)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        # Must exceed SOURAN_DOH_BUDGET so a slow-but-successful DoH
        # lookup still reaches the client instead of timing out.
        self.request.settimeout(float(os.environ.get("SOURAN_CLIENT_TIMEOUT", "20")))
        try:
            head = self._recv_exact(2)
            if not head:
                return
            (length,) = struct.unpack("!H", head)
            msg = self._recv_exact(length)
            if msg is None or len(msg) < 12:
                return
            _qid, flags, qd = struct.unpack("!HHH", msg[:6])
            # Only QUERY (0) is supported. STATUS/NOTIFY/UPDATE must be
            # refused with NOTIMP, as unbound itself does. Previously the
            # front-end ignored the opcode and rewrote the reply header,
            # which converted NOTIMP into a successful answer and leaked A
            # records in response to an UPDATE.
            if ((flags >> 11) & 0x0F) != 0:
                resp = struct.pack("!HHHHHH", _qid, 0x8404, qd, 0, 0, 0)
                self.request.sendall(struct.pack("!H", len(resp)) + resp)
                return
            off = 12
            qname = None
            qtype = 1
            for _ in range(qd):
                name, off = _decode_name(msg, off)
                if name is None:
                    return
                qname = name.rstrip(".")
                if off + 4 > len(msg):
                    return
                qtype, _qc = struct.unpack("!HH", msg[off:off + 4])
                off += 4
            if not qname:
                return
            answer, _fb = resolve(qname, qtype)
            if answer is None or len(answer) < 12:
                resp = struct.pack("!HHHHHH", _qid, 0x8182, qd, 0, 0, 0) + \
                    msg[12:12 + len(qname) + 5]
            else:
                # Keep the original transaction ID and force QR|RD|RA so
                # clients accept the reply. Rewrite bytes 0..3 only; the
                # answer section must be passed through untouched.
                new_flags = 0x8000 | 0x0080 | (flags & 0x0100)
                resp = struct.pack("!H", _qid) + struct.pack("!H", new_flags) + \
                    answer[4:]
            self.request.sendall(struct.pack("!H", len(resp)) + resp)
        except (socket.timeout, OSError, struct.error):
            return

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.request.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf


class UDPHandler(socketserver.BaseRequestHandler):
    """UDP responder. LAN stub resolvers use UDP, so both are required."""

    def handle(self):
        data, sock = self.request
        if len(data) < 12:
            return
        _qid, flags, qd = struct.unpack("!HHH", data[:6])
        # Offset just past the question section, so the TC/truncation reply can
        # echo the question verbatim instead of re-deriving its length from the
        # qname string (which was one byte short and corrupted the reply).
        qd_end = _question_end(data)
        # Only QUERY (0); see the note in Handler.handle(). A non-QUERY
        # opcode must get NOTIMP, never a rewritten successful answer.
        if ((flags >> 11) & 0x0F) != 0:
            resp = struct.pack("!HHHHHH", _qid, 0x8404, qd, 0, 0, 0)
            try:
                sock.sendto(resp, self.client_address)
            except OSError:
                return
            return
        off = 12
        qname = None
        qtype = 1
        for _ in range(qd):
            name, off = _decode_name(data, off)
            if name is None:
                return
            qname = name.rstrip(".")
            if off + 4 > len(data):
                return
            qtype, _qc = struct.unpack("!HH", data[off:off + 4])
            off += 4
        if not qname:
            return
        answer, _fb = resolve(qname, qtype)
        if answer is None or len(answer) < 12:
            resp = struct.pack("!HHHHHH", _qid, 0x8182, qd, 0, 0, 0) + \
                data[12:12 + len(qname) + 5]
        else:
            new_flags = 0x8000 | 0x0080 | (flags & 0x0100)
            resp = struct.pack("!H", _qid) + struct.pack("!H", new_flags) + \
                answer[4:]
        # Never emit a reply larger than the client's advertised buffer;
        # set TC so the client retries over TCP instead of dropping.
        #
        # v4.3.3 fixes two defects here, both visible to clients as
        # "dig: Message parser reports malformed message packet" on any TXT
        # set too large for UDP:
        #   1. The echoed question was sliced as data[12:12+len(qname)+5].
        #      An encoded name needs sum(1+len(label))+1 bytes (each label has a
        #      length byte, plus a root zero byte) and the question then needs
        #      4 more for QTYPE+QCLASS. For cloudflare.com that is 20 bytes, not
        #      19 — the slice cut the final QCLASS byte and the client's parser
        #      rejected the whole message.
        #   2. client_buf was read from data[10:12], which is NSCOUNT+ARCOUNT,
        #      not the advertised UDP payload size. A client sending EDNS with
        #      NSCOUNT=0/ARCOUNT=1 made client_buf 1, so `len(resp) > 1` was
        #      true for every reply and large-but-legal answers were truncated
        #      needlessly. The real size lives in the EDNS0 OPT RR.
        try:
            client_buf = _edns_bufsize(data) or 1232
        except Exception:
            client_buf = 1232
        if len(resp) > max(512, client_buf):
            # RFC 1035 §4.1.1: an over-large UDP reply must be NOERROR with TC
            # set, so the client retries over TCP. v4.2.1 emitted 0x8382, whose
            # low 4 bits are rcode 2 (SERVFAIL), so the client saw a hard
            # failure instead of a truncation hint and dig reported
            # "Message parser reports malformed message packet".
            resp = struct.pack("!HHHHHH", _qid, 0x8380, qd, 0, 0, 0) + data[12:qd_end]
        try:
            sock.sendto(resp, self.client_address)
        except OSError:
            return


class UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class HealthHandler(socketserver.StreamRequestHandler):
    """Plain HTTP endpoint for health checks / dashboard."""
    def handle(self):
        try:
            req = self.rfile.readline(4096).decode("latin-1", "replace")
            path = req.split(" ")[1] if " " in req else "/"
            while True:
                line = self.rfile.readline(1024)
                if not line or line in (b"\r\n", b"\n"):
                    break
            if path.startswith("/health"):
                body = json.dumps({
                    "status": "ok",
                    "port": LISTEN_PORT,
                    "primary_upstream": f"{UPSTREAM_BIND[0]}:{UPSTREAM_BIND[1]}",
                    "doh_fallback": FALLBACK_URL,
                    "doh_secondary": SECONDARY_URL,
                    "cache_entries": len(_cache),
                    "stats": STATS,
                    "note": "tier1=local unbound iterative, tier2=DoH/443 when "
                            "tier1 is empty or returns injected private addresses",
                }).encode()
                resp = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                        b"Content-Length: " + str(len(body)).encode() +
                        b"\r\nConnection: close\r\n\r\n" + body)
                self.wfile.write(resp)
            else:
                self.wfile.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n"
                                 b"Connection: close\r\n\r\n")
        except (OSError, ValueError):
            return


class DoTHandler(socketserver.StreamRequestHandler):
    """DNS-over-TLS front-end.

    The DoT instance is its own recursive resolver, so it suffers the same
    forged answers. Terminating TLS here and reusing resolve() means DoT
    gets the identical poison-proof guarantee as the :53 front-end.
    """

    def handle(self):
        self.request.settimeout(float(os.environ.get("SOURAN_CLIENT_TIMEOUT", "25")))
        try:
            self.request.settimeout(30)
            head = self._recv_exact(2)
            if not head:
                return
            (length,) = struct.unpack("!H", head)
            msg = self._recv_exact(length)
            if msg is None or len(msg) < 12:
                return
            _qid, flags, qd = struct.unpack("!HHH", msg[:6])
            # Only QUERY (0) is supported. STATUS/NOTIFY/UPDATE must be
            # refused with NOTIMP, as unbound itself does. Previously the
            # front-end ignored the opcode and rewrote the reply header,
            # which converted NOTIMP into a successful answer and leaked A
            # records in response to an UPDATE.
            if ((flags >> 11) & 0x0F) != 0:
                resp = struct.pack("!HHHHHH", _qid, 0x8404, qd, 0, 0, 0)
                self.request.sendall(struct.pack("!H", len(resp)) + resp)
                return
            off = 12
            qname = None
            qtype = 1
            for _ in range(qd):
                name, off = _decode_name(msg, off)
                if name is None:
                    return
                qname = name.rstrip(".")
                if off + 4 > len(msg):
                    return
                qtype, _qc = struct.unpack("!HH", msg[off:off + 4])
                off += 4
            if not qname:
                return
            answer, _fb = resolve(qname, qtype)
            if answer is None or len(answer) < 12:
                resp = struct.pack("!HHHHHH", _qid, 0x8182, qd, 0, 0, 0) + \
                    msg[12:12 + len(qname) + 5]
            else:
                new_flags = 0x8000 | 0x0080 | (flags & 0x0100)
                resp = struct.pack("!H", _qid) + struct.pack("!H", new_flags) + \
                    answer[4:]
            self.request.sendall(struct.pack("!H", len(resp)) + resp)
        except (socket.timeout, OSError, struct.error):
            return

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.request.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf


class DoTServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def get_request(self):
        sock, addr = self.socket.accept()
        import ssl as _ssl
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(os.environ.get("SOURAN_TLS_CERT",
                                           "/opt/souran-ai/config/doh.pem"),
                            os.environ.get("SOURAN_TLS_KEY",
                                           "/opt/souran-ai/config/doh.key"))
        try:
            return ctx.wrap_socket(sock, server_side=True), addr
        except OSError:
            try:
                sock.close()
            except OSError:
                pass
            raise


def main():
    resolver = Server((LISTEN_HOST, LISTEN_PORT), Handler)
    health = Server((LISTEN_HOST, LISTEN_PORT + 1), HealthHandler)
    threading.Thread(target=health.serve_forever, daemon=True).start()

    dot = None
    dot_port = int(os.environ.get("SOURAN_DOT_PORT", "0") or 0)
    if dot_port:
        try:
            dot = DoTServer((LISTEN_HOST, dot_port), DoTHandler)
            threading.Thread(target=dot.serve_forever, daemon=True).start()
        except Exception as exc:
            print(f"[souran-doh-fallback] DoT :{dot_port} unavailable ({exc})",
                  file=sys.stderr, flush=True)

    udp = None
    if LISTEN_UDP:
        try:
            udp = UDPServer((LISTEN_HOST, LISTEN_PORT), UDPHandler)
            threading.Thread(target=udp.serve_forever, daemon=True).start()
        except OSError as exc:
            print(f"[souran-doh-fallback] UDP :{LISTEN_PORT} unavailable "
                  f"({exc}); TCP only", file=sys.stderr, flush=True)

    print(f"[souran-doh-fallback] DNS {LISTEN_HOST}:{LISTEN_PORT} "
          f"tcp+{'udp' if udp else 'tcp-only'} health :{LISTEN_PORT + 1} "
          f"primary={UPSTREAM_BIND[0]}:{UPSTREAM_BIND[1]} "
          f"doh={FALLBACK_URL} proxy={PROXY}"
          + (f" dot=:{dot_port}" if dot else ""), flush=True)
    try:
        resolver.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()