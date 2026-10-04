#!/usr/bin/env python3
"""
SOURAN AI NETWORK SERVER v4.2.0 — Web3 DNS Resolver
File: souran_web3_resolver.py

Resolves blockchain domain names through the Souran DNS front-end.
Supports: ENS (.eth), Handshake (.hua), Unstoppable Domains

Behaviours:
  - ENS: resolves .eth names via Ethereum RPC (Cloudflare's public 1.1.1.1/ethapi)
  - Handshake: resolves .hua names via HNS DNS seeds
  - Unstoppable: resolves .crypto/.nft/.wallet/.x/.bitcoin/.blockchain/.dao/.888/.polygon/.nexus
    via Unstoppable API fallback
  - Caches results in memory with TTL
  - Exposes /api/web3/resolve and /api/web3/ens endpoints

Design: pure stdlib, integrates with the existing souran-doh-fallback.py front-end.
"""

import json, os, socket, struct, subprocess, sys, threading, time, urllib.request
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.0.0"
CACHE_DIR = Path("/opt/souran-ai/data/web3-cache")
STATE_FILE = CACHE_DIR / "web3-state.json"

# TTLs (seconds)
TTL_ENS = 300
TTL_HANDSHAKE = 300
TTL_UNSTOPPABLE = 300

# Ethereum RPC — public, keyless endpoints tried in order.
#
# v1.0.0 used only "https://1.1.1.1/eth-api/v1/rpc/mainnet", which now answers
# HTTP 301 and has no response body, so every ENS lookup silently returned
# {"addresses": []} — the feature looked installed but resolved nothing.
# Measured 2026-10-04 through the local bypass proxy:
#   1.1.1.1/eth-api           -> 301 (dead)
#   eth.llamarpc.com          -> 525
#   rpc.ankr.com/eth          -> 401 Unauthorized (key now required)
#   cloudflare-eth.com        -> -32046 cannot fulfil
#   ethereum-rpc.publicnode.com -> 200, live block number
# Keep several live endpoints so one being retired does not silently break ENS.
ETH_RPC_ENDPOINTS = [
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://rpc.ankr.com/eth",
    "https://cloudflare-eth.com",
]
# Backwards-compatible alias for any code that referenced the single URL.
ETH_RPC = ETH_RPC_ENDPOINTS[0]

# ENS Registry (the contract that maps a namehash -> resolver address).
# NOT the Public Resolver (0x3671aE578E63FdF66ad4F3E12CC0c0d71Ac7510C) — v1.0.0
# queried the wrong contract here, every call reverted, and ENS silently
# resolved nothing.
ENS_REGISTRY = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"

# Outbound RPC proxy. curl honours this explicitly; it is passed as --proxy
# rather than relying on inherited env so the service behaves the same whether
# started by systemd (no shell proxy) or from a terminal.
ETH_RPC_PROXY = os.environ.get("SOURAN_PROXY", "http://127.0.0.1:8118")


def _abi_to_address(result) -> str:
    """Normalise an ABI-encoded `address` return value to a 20-byte hex address.

    Solidity returns an address as a LEFT-padded 32-byte word:
        0x000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045
    Taking chars 2..42 (what v1.0.0 did) yields 000000000000000000000000d8da6bf2
    — 12 leading zero bytes and a TRUNCATED address. The address is the LAST
    20 bytes. Verified: this is what returns vitalik.eth's real address
    (0xd8da6bf26964af9d7eed9e03e53415d37aa96045).

    Returns "" for a zero address (no owner / no resolver set).
    """
    if not isinstance(result, str):
        return ""
    raw = result.strip()
    if not raw.startswith("0x"):
        return ""
    body = raw[2:]
    if len(body) < 40:
        return ""
    addr = body[-40:].lower()
    if set(addr) == {"0"}:
        return ""
    return "0x" + addr


def _decode_ens_string(abi_bytes: bytes) -> str:
    """Decode an ABI-encoded `string` return value.

    Layout: 32-byte offset, 32-byte length, then `length` bytes of UTF-8.
    The v1.0.0 code sliced a fixed 130 hex chars off the front, which is only
    correct when the offset word is exactly 0x20 — decode it properly instead.
    """
    if len(abi_bytes) < 64:
        return ""
    offset = int.from_bytes(abi_bytes[0:32], "big")
    if offset + 32 > len(abi_bytes):
        return ""
    length = int.from_bytes(abi_bytes[offset:offset + 32], "big")
    start = offset + 32
    if length == 0 or start + length > len(abi_bytes):
        return ""
    return abi_bytes[start:start + length].decode("utf-8", "replace")

# Handshake DNS seeds
HNS_SEEDS = [
    "seed.hNS.mandragora.org",
    "seed.hns.matched.cn",
    "hns.zone",
]

# Unstoppable domains API
UNSTOPPABLE_API = "https://api.unstoppabledomains.com/public/v1"

# Known TLDs
ENS_TLD = ".eth"
HNS_TLD = ".hua"
UNSTOPPABLE_TLDS = {".crypto", ".nft", ".wallet", ".x", ".bitcoin",
                     ".blockchain", ".dao", ".888", ".polygon", ".nexus", ".zil"}

# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------
cache = OrderedDict()  # domain -> (answers, ttl, expiry)
CACHE_MAX = 10000

def _cache_get(domain: str):
    entry = cache.get(domain)
    if entry and entry[2] > time.time():
        return entry[0]
    cache.pop(domain, None)
    return None

def _cache_set(domain: str, answers: list, ttl: int):
    if domain in cache:
        cache.move_to_end(domain)
    cache[domain] = (answers, ttl, time.time() + ttl)
    if len(cache) > CACHE_MAX:
        cache.popitem(last=False)

# ---------------------------------------------------------------------------
# ENS resolution
# ---------------------------------------------------------------------------
def _ethrpc(method: str, params: list) -> dict:
    """Call Ethereum JSON-RPC, trying each known-good endpoint in turn.

    Two fixes over v1.0.0:

    1. Multiple endpoints. The single hardcoded URL now answers HTTP 301, so
       every ENS lookup failed. Endpoints are tried in turn and the failure
       reason surfaces if none work.
    2. Shells out to `curl`. Python's own TLS ClientHello is DPI-reset on this
       network (urllib raises 403/timeout on every RPC host) while curl's is
       not — the same measured constraint that forces the DNS resolver's DoH
       tier through curl.
    """
    body = json.dumps({"jsonrpc": "2.0", "method": method,
                       "params": params, "id": 1}).encode()
    last_err = None
    for url in ETH_RPC_ENDPOINTS:
        cmd = ["curl", "-s", "--max-time", "20", "-q",
               "-H", "Content-Type: application/json",
               "--data-binary", "@-", url]
        if ETH_RPC_PROXY:
            cmd[1:1] = ["--proxy", ETH_RPC_PROXY]
        try:
            proc = subprocess.run(cmd, input=body, capture_output=True, timeout=25)
            if proc.returncode != 0:
                last_err = f"{url}: curl rc={proc.returncode}"
                continue
            doc = json.loads(proc.stdout.decode("utf-8", "replace"))
            if isinstance(doc, dict) and doc.get("error"):
                last_err = f"{url}: {doc['error']}"
                continue
            return doc
        except Exception as exc:
            last_err = f"{url}: {type(exc).__name__} {exc}"
            continue
    raise RuntimeError(f"all ETH RPC endpoints failed; last: {last_err}")

def resolve_ens(domain: str) -> list:
    """Resolve an .eth domain to its Ethereum address."""
    # ENS namehash covers the FULL name including the TLD: namehash('vitalik.eth'),
    # not namehash('vitalik'). v1.0.0 stripped '.eth' first and then hashed the
    # remainder, which is a different, unregistered name — the registry returned
    # a zero resolver and the lookup silently produced nothing.
    name = domain.rstrip(".").lower()

    # Step 1: ask the ENS REGISTRY (not the Public Resolver) for the
    # resolver contract of this name.
    #
    # v1.0.0 called resolver(bytes32) on 0x3671aE...7510C, which is the Public
    # RESOLVER. The registry is 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e.
    # The call therefore reverted ("execution reverted") and the code caught
    # the exception and returned [] — so ENS never resolved anything.
    try:
        node = _namehash(name)[2:]        # strip the 0x prefix for ABI encoding
        result = _ethrpc("eth_call", [{
            "to": ENS_REGISTRY,
            "data": "0x0178b8bf" + node,   # resolver(bytes32)
        }, "latest"])
        resolver = _abi_to_address(result.get("result"))
        if not resolver:
            return []
    except Exception:
        return []

    # Step 2: ask that resolver for the owner's address: addr(bytes32).
    try:
        result = _ethrpc("eth_call", [{
            "to": resolver,
            "data": "0x3b3b57de" + node,
        }, "latest"])
        addr = _abi_to_address(result.get("result"))
        if addr:
            return [addr]
    except Exception:
        pass

    # Step 3: fall back to a text record (useful for .eth names that only
    # publish a URL / content hash).
    try:
        key = "ipfs.html.value"
        key_hex = key.encode().hex()
        enc = (node
               + "%064x" % 32
               + "%064x" % len(key)
               + key_hex.ljust(64, "0"))
        result = _ethrpc("eth_call", [{"to": resolver,
                                       "data": "0x59d1d43c" + enc}, "latest"])
        text_result = (result.get("result") or "0x").strip()
        if text_result.startswith("0x") and len(text_result) > 130:
            body = bytes.fromhex(text_result[2:])
            try:
                decoded = _decode_ens_string(body)
                if decoded:
                    return [decoded]
            except Exception:
                pass
    except Exception:
        pass

    return []

def _namehash(name: str) -> str:
    """Compute ENS namehash (EIP-137) as a 0x-prefixed hex string.

    v1.0.0 mixed types: `_keccak256()` returns 32 raw BYTES, but this
    function called `bytes.fromhex()` on its return value, raising
    `ValueError: non-hexadecimal number found in fromhex() arg at position 0`
    on every single-label name. That exception was swallowed by the API
    handler, so ENS lookups returned empty addresses forever.
    """
    if not name:
        return "0x" + "00" * 32
    node = b"\x00" * 32
    for label in reversed(name.split(".")):
        if not label:
            continue
        node = _keccak256(node + _keccak256(label.encode("utf-8")))
    return "0x" + node.hex()

def _keccak256(data: bytes) -> bytes:
    """Keccak-256 as Ethereum uses it (NOT hashlib.sha3_256).

    v1.0.0 used hashlib.sha3_256 with the comment "Python's sha3_256 IS
    keccak256". That is false — they differ in the domain-separation byte
    (0x06 for NIST SHA3, 0x01 for Keccak), so every namehash was wrong and ENS
    lookups silently returned no addresses. pycryptodome is unusable here
    (its Debian path is shadowed by this interpreter's 3.14 dist-packages), so
    a verified pure-stdlib implementation lives in souran_keccak.py.
    """
    from souran_keccak import keccak256
    return keccak256(data)

# ---------------------------------------------------------------------------
# Handshake resolution
# ---------------------------------------------------------------------------
def resolve_handshake(domain: str) -> list:
    """Resolve a .hua Handshake domain via DNS seeds."""
    name = domain[:-4] if domain.endswith(".hua") else domain

    for seed in HNS_SEEDS:
        try:
            cmd = ["dig", "+time=5", "+tries=1", f"@{seed}", f"{name}.hua", "A"]
            import subprocess
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if p.returncode == 0:
                ips = []
                for line in p.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 5 and parts[-1].replace(".", "").isdigit():
                        ips.append(parts[-1])
                if ips:
                    return ips
        except Exception:
            continue
    return []

# ---------------------------------------------------------------------------
# Unstoppable Domains resolution
# ---------------------------------------------------------------------------
def resolve_unstoppable(domain: str) -> list:
    """Resolve an Unstoppable Domain via their public API."""
    tld = None
    for t in UNSTOPPABLE_TLDS:
        if domain.endswith(t):
            tld = t
            break
    if not tld:
        return []

    # Try the public API
    try:
        url = f"{UNSTOPPABLE_API}/domains/{domain}"
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        # Extract crypto addresses
        addresses = data.get("meta", {}).get("acceptedCryptocurrencies", [])
        if addresses:
            return [f"unstoppable:{domain}:{','.join(addresses[:5])}"]
        # Try IPFS gateway
        ipfs = data.get("records", {}).get("ipfs.html", "")
        if ipfs:
            return [f"https://{ipfs}.ipfs.dweb.link"]
    except Exception:
        pass

    # Fallback: try DNS resolution for the domain
    try:
        cmd = ["dig", "+time=5", "+tries=1", domain, "A"]
        import subprocess
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if p.returncode == 0 and "ANSWER SECTION" in p.stdout:
            ips = []
            body = p.stdout.split("ANSWER SECTION:", 1)[1]
            for line in body.splitlines():
                parts = line.split()
                if parts and parts[-1].replace(".", "").isdigit():
                    ips.append(parts[-1])
            if ips:
                return ips
    except Exception:
        pass

    return []

# ---------------------------------------------------------------------------
# Main resolver
# ---------------------------------------------------------------------------
def resolve(domain: str) -> dict:
    """Resolve a Web3 domain. Returns {domain, type, answers, ttl, error}."""
    domain = domain.lower().rstrip(".")

    # Check cache
    cached = _cache_get(domain)
    if cached is not None:
        return {"domain": domain, "type": "cached", "answers": cached, "ttl": 0}

    answers = []
    rec_type = "unknown"

    if domain.endswith(ENS_TLD):
        rec_type = "ens"
        answers = resolve_ens(domain)
        ttl = TTL_ENS
    elif domain.endswith(HNS_TLD):
        rec_type = "handshake"
        answers = resolve_handshake(domain)
        ttl = TTL_HANDSHAKE
    else:
        for tld in UNSTOPPABLE_TLDS:
            if domain.endswith(tld):
                rec_type = "unstoppable"
                answers = resolve_unstoppable(domain)
                ttl = TTL_UNSTOPPABLE
                break

    if answers:
        _cache_set(domain, answers, ttl)
        return {"domain": domain, "type": rec_type, "answers": answers, "ttl": ttl}

    return {"domain": domain, "type": rec_type, "answers": [], "ttl": 0,
            "error": "no records found"}

# ---------------------------------------------------------------------------
# HTTP API
# ---------------------------------------------------------------------------
def start_api():
    """Start the Web3 resolver API on port 8086."""
    import http.server

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/api/web3/resolve"):
                qs = urllib.parse.urlparse(self.path).query
                params = urllib.parse.parse_qs(qs)
                domain = params.get("name", [None])[0]
                if not domain:
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "missing name parameter"}).encode())
                    return
                result = resolve(domain)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(result, indent=2).encode())

            elif self.path.startswith("/api/web3/ens"):
                qs = urllib.parse.urlparse(self.path).query
                params = urllib.parse.parse_qs(qs)
                name = params.get("name", [None])[0]
                if not name:
                    self.send_response(400)
                    self.end_headers()
                    return
                result = resolve_ens(name + ".eth" if not name.endswith(".eth") else name)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"name": name, "addresses": result}).encode())

            elif self.path == "/health":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ok", "port": 8086, "version": VERSION}).encode())
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format, *args):
            pass

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 8086), Handler)
    print(f"[web3-resolver v{VERSION}] API on :8086", flush=True)
    server.serve_forever()

if __name__ == "__main__":
    start_api()