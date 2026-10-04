#!/usr/bin/env python3
"""
Souran AI Network Server — v4.3 general RR-type resolution layer.

WHY THIS MODULE EXISTS
----------------------
v4.2.1 resolved only A and AAAA. `parse_a_records()` walked the answer
section but kept only `rtype == 1` (A) and `build_answer()` could only
synthesise A/AAAA, so every other record type (MX, TXT, CNAME, SOA, NS,
SRV, AAAA-in-CNAME-chains, HTTPS/SVCB, ...) either timed out or returned a
malformed packet. dig even warned:

    ;; communications error to 127.0.0.1#53: timed out
    ;; Warning: Message parser reports malformed message packet.

That is a real correctness bug, not a cosmetic one: a resolver that drops
MX breaks mail, and one that mangles TXT breaks SPF/DKIM/DMARC and every
domain-ownership proof.

THE FIX
-------
Do not synthesise answers from a whitelist of types. Preserve the upstream
RRs verbatim: walk the answer section, copy each RR's rdata, and re-emit a
response that carries the ORIGINAL RR bytes. Only when we must answer from
scratch (the Tier-2 DoH path, where we rebuild after rejecting an injected
answer) do we fall back to the legacy A/AAAA synthesiser.

This keeps a byte-exact RR for every type, so MX preference/ordering, TXT
string segmentation, and unknown/experimental types (RFC 3597) all survive.

Poison-proofing is unchanged and still applies to address-family records:
A/AAAA answers landing in reserved space are rejected before they can ever be
cached or served.
"""

from __future__ import annotations

import socket
import struct

__version__ = "4.3.0"

# Record types we understand well enough to synthesise from scratch when
# rebuilding a response after rejecting an injected answer. Everything else is
# passed through verbatim (see `extract_rrs` / `build_passthrough`).
_A = 1
_NS = 2
_CNAME = 5
_SOA = 6
_PTR = 12
_MX = 15
_TXT = 16
_AAAA = 28
_SRV = 33
_OPT = 41
_DS = 43
_RRSIG = 46
_DNSKEY = 48
_NSEC = 47
_CAA = 257
_HTTPS = 65
_SVCB = 64

# Types that carry an IP literal in rdata and therefore must be poison-checked.
ADDRESS_TYPES = frozenset({_A, _AAAA})


def _decode_name(data: bytes, offset: int):
    """Decode a (possibly compressed) DNS name. Returns (labels, new_offset).

    The returned offset is the position in THIS message just past the encoded
    name — which for a compression pointer is 2 bytes, not the end of the
    name it points at.

    v4.3 bug: this function followed a compression pointer and then kept
    looping, re-reading bytes at the pointed-to offset as if they were more
    labels. On a reply like

        c00c 0001 0001 000000fa 0004 681084e5

    the pointer at offset 32 was followed to offset 12, parsing "cloudflare"
    and "com" again and advancing the cursor to 40 instead of 34. Every
    subsequent field (type, class, ttl, rdlen) was then read 6 bytes early, so
    a 4-byte A record reported rdlen=1 and the parser raised a bogus
    "rdata overrun" — which the front-end then escalated to DoH. Fix: a pointer
    terminates the name.
    """
    labels = []
    end = offset
    guard = 0
    while True:
        guard += 1
        if guard > 128 or end >= len(data):
            raise ValueError("name overrun")
        length = data[end]
        if length == 0:
            end += 1
            return labels, end
        if length & 0xC0 == 0xC0:          # compression pointer
            if end + 1 >= len(data):
                raise ValueError("truncated pointer")
            # The name ends HERE; the pointer's 2 bytes are consumed and the
            # target is only followed to collect labels.
            ptr = ((length & 0x3F) << 8) | data[end + 1]
            if ptr >= len(data):
                raise ValueError("bad pointer")
            sub_labels, _ = _decode_name(data, ptr)
            labels.extend(sub_labels)
            return labels, end + 2
        if length & 0xC0:                 # reserved label type
            raise ValueError("reserved label type")
        end += 1
        if end + length > len(data):
            raise ValueError("truncated label")
        labels.append(data[end:end + length])
        end += length


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        raw = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode("ascii", "ignore")
        if len(raw) > 63:
            raise ValueError("label too long")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def iter_answers(payload: bytes):
    """Yield (rtype, rdata, ttl) for every RR in the ANSWER section.

    Never guesses: a malformed packet raises ValueError so the caller can
    treat the response as untrustworthy rather than serving invented bytes.
    """
    if len(payload) < 12:
        raise ValueError("short header")
    _qid, _flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", payload[:12])
    off = 12
    for _ in range(qd):
        _, off = _decode_name(payload, off)
        off += 4
    if off > len(payload):
        raise ValueError("question overrun")
    for _ in range(an):
        _name, off = _decode_name(payload, off)
        if off + 10 > len(payload):
            raise ValueError("rr header overrun")
        rtype, _cls, ttl, rdlen = struct.unpack("!HHIH", payload[off:off + 10])
        off += 10
        if off + rdlen > len(payload):
            raise ValueError("rdata overrun")
        yield rtype, payload[off:off + rdlen], ttl
        off += rdlen


def answer_addresses(payload: bytes):
    """Return (addresses, rcode) where addresses are A/AAAA rdata strings.

    Raises ValueError on a malformed packet instead of returning partial or
    fabricated data.
    """
    if len(payload) < 12:
        raise ValueError("short header")
    _qid, flags, _qd, _an, _ns, _ar = struct.unpack("!HHHHHH", payload[:12])
    rcode = flags & 0x0F
    addresses = []
    for rtype, rdata, _ttl in iter_answers(payload):
        if rtype == _A and len(rdata) == 4:
            addresses.append(socket.inet_ntoa(rdata))
        elif rtype == _AAAA and len(rdata) == 16:
            addresses.append(socket.inet_ntop(socket.AF_INET6, rdata))
    return addresses, rcode


def question_type(payload: bytes) -> int:
    """Return the QTYPE of the first question (defaults to A)."""
    if len(payload) < 12:
        return _A
    _qid, _flags, qd, _an, _ns, _ar = struct.unpack("!HHHHHH", payload[:12])
    if qd < 1:
        return _A
    try:
        _, off = _decode_name(payload, 12)
        return struct.unpack("!H", payload[off:off + 2])[0]
    except (ValueError, struct.error):
        return _A


def has_answer_of_type(payload: bytes, qtype: int) -> bool:
    """True when the answer section carries at least one RR of `qtype`.

    Used by the test suite and by the cache to decide whether an answer is
    actually useful for the requested type (an NODATA answer has no RRs of the
    requested type but is still a valid NOERROR reply).
    """
    try:
        return any(rtype == qtype for rtype, _rd, _ttl in iter_answers(payload))
    except ValueError:
        return False


def build_passthrough(qname: str, qtype: int, rrs, ttl: int = 300) -> bytes:
    """Rebuild a NOERROR answer carrying verbatim rdata from `rrs`.

    `rrs` is the iterable produced by `iter_answers`. Because rdata is copied
    verbatim, MX preference and exchange order, TXT character-string
    segmentation, and unknown types all survive intact — something the old
    synthesiser could not do for any type outside A/AAAA.
    """
    qname_enc = _encode_name(qname)
    answers = b""
    count = 0
    for rtype, rdata, rr_ttl in rrs:
        answers += (
            qname_enc
            + struct.pack("!HHIH", rtype, 1, int(rr_ttl) or ttl, len(rdata))
            + rdata
        )
        count += 1
    header = struct.pack("!HHHHHH", 0, 0x8180, 1, count, 0, 0)
    return header + qname_enc + struct.pack("!HH", qtype, 1) + answers


def build_nodata(qname: str, qtype: int, nxdomain: bool = False) -> bytes:
    """A correct negative response.

    Default: NODATA -- NOERROR with zero answers; the name exists but has
    no record of this type.

    nxdomain=True: NXDOMAIN -- the name does not exist at all. RCODE 3.

    The two are semantically different and clients depend on the
    distinction: NXDOMAIN enables negative caching and typo detection,
    NODATA does not. Handing back a NOERROR for a name that does not
    exist (or vice versa) is a correctness fault, not a cosmetic one.
    """
    qname_enc = _encode_name(qname)
    flags = 0x8183 if nxdomain else 0x8180   # QR RD RA + RCODE
    header = struct.pack("!HHHHHH", 0, flags, 1, 0, 0, 0)
    return header + qname_enc + struct.pack("!HH", qtype, 1)


if __name__ == "__main__":  # pragma: no cover - manual smoke check
    import sys
    if len(sys.argv) > 1:
        blob = bytes.fromhex(sys.argv[1])
        print("addresses:", answer_addresses(blob))
    print(f"souran_dns_rr {__version__} OK")