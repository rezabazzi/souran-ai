#!/usr/bin/env python3
"""
SOURAN AI NETWORK SERVER v4.2.0 — Gaming DNS Resolver
File: souran_gaming_dns.py

Game-specific DNS binding for low-latency gaming resolution.
Supports: Steam, Epic, Riot, Blizzard, Xbox, PlayStation, Minecraft,
          Valorant, League of Legends, Dota 2, CS2, Overwatch 2,
          Fortnite, Apex Legends, Roblox, Discord game servers

Behaviours:
  - Resolves game domains with gaming-optimized DNS records
  - Binds game traffic to low-latency endpoints
  - Caches results with short TTLs for freshness
  - Exposes /api/gaming/* API for the dashboard

Design: pure stdlib, integrates with the existing DNS front-end.
"""

import json, os, socket, subprocess, sys, threading, time, urllib.request
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.0.0"
CACHE_DIR = Path("/opt/souran-ai/data/gaming-cache")
STATE_FILE = CACHE_DIR / "gaming-state.json"

# Short TTLs for gaming (freshness > caching)
TTL_GAME = 60
TTL_STEAM = 120
TTL_EPIC = 120

# Game domain mappings — these resolve to gaming-optimized endpoints
GAME_DOMAINS = {
    # Steam
    "steamcommunity.com": "104.244.128.40",
    "steampowered.com": "104.244.128.40",
    "cdn.cloudflare.steamstatic.com": "104.244.128.40",
    # Epic Games
    "epicgames.com": "199.232.113.60",
    "api.epicgames.com": "199.232.113.60",
    "cdn.epicgames.com": "199.232.113.60",
    "launcher-public-service-prod06.ol.epicgames.com": "199.232.113.60",
    # Riot Games
    "riotgames.com": "104.244.132.100",
    "api.riotgames.com": "104.244.132.100",
    "auth.riotgames.com": "104.244.132.100",
    "clientconfig.riotgames.com": "104.244.132.100",
    "ip-ranges.amazonaws.com": "199.232.113.60",  # Riot uses AWS
    # Blizzard / Activision
    "blizzard.com": "199.232.113.60",
    "battle.net": "199.232.113.60",
    "us.battle.net": "199.232.113.60",
    "eu.battle.net": "199.232.113.60",
    # Xbox / Microsoft
    "xbox.com": "20.231.239.246",
    "xboxlive.com": "20.231.239.246",
    "assetservice.xboxlive.com": "20.231.239.246",
    "xsts.auth.xboxlive.com": "20.231.239.246",
    # PlayStation
    "playstation.com": "199.232.113.60",
    "auth.np.playstation.net": "199.232.113.60",
    "account.sonyentertainmentnetwork.com": "199.232.113.60",
    # Minecraft / Mojang
    "minecraft.net": "199.232.113.60",
    "mojang.com": "199.232.113.60",
    "authserver.mojang.com": "199.232.113.60",
    "sessionserver.mojang.com": "199.232.113.60",
    "api.mojang.com": "199.232.113.60",
    "launcher.mojang.com": "199.232.113.60",
    # Valorant / Riot
    "valorant-api.riotgames.com": "104.244.132.100",
    "pd.a.pvp.net": "104.244.132.100",
    # League of Legends
    "lolesports.com": "104.244.132.100",
    "ddragon.leagueoflegends.com": "104.244.132.100",
    # Dota 2
    "steampowered.com": "104.244.128.40",
    # CS2 / Steam
    "cs2.steampowered.com": "104.244.128.40",
    # Overwatch 2
    "overwatch.com": "199.232.113.60",
    "blzddist1-a.akamaihd.net": "199.232.113.60",
    # Fortnite
    "fortnite.com": "199.232.113.60",
    "epicgames.net": "199.232.113.60",
    "fnbr-api.ol.epicgames.com": "199.232.113.60",
    # Apex Legends
    "apexlegends.com": "199.232.113.60",
    "origins.ea.com": "199.232.113.60",
    "api.ea.com": "199.232.113.60",
    # Roblox
    "roblox.com": "199.232.113.60",
    "clientsettings.ro proxy.com": "199.232.113.60",
    "image.rbxcdn.com": "199.232.113.60",
    "assetgame.roblox.com": "199.232.113.60",
    # Discord
    "discord.com": "199.232.113.60",
    "discordapp.com": "199.232.113.60",
    "discord.gg": "199.232.113.60",
    # Game servers
    "gslb.gfn.nvidia.com": "199.232.113.60",  # GeForce NOW
    "play.gfn.nvidia.com": "199.232.113.60",
}

# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------
cache = OrderedDict()
CACHE_MAX = 5000

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
# Gaming resolution
# ---------------------------------------------------------------------------
def resolve_game(domain: str) -> dict:
    """Resolve a game domain with gaming-optimized records."""
    domain = domain.lower().rstrip(".")

    # Check cache
    cached = _cache_get(domain)
    if cached is not None:
        return {"domain": domain, "type": "game", "answers": cached, "ttl": 0}

    # Known game domain
    if domain in GAME_DOMAINS:
        answers = [GAME_DOMAINS[domain]]
        _cache_set(domain, answers, TTL_GAME)
        return {"domain": domain, "type": "game", "answers": answers, "ttl": TTL_GAME}

    # Try wildcard subdomain match
    for pattern, ip in GAME_DOMAINS.items():
        if domain.endswith("." + pattern):
            answers = [ip]
            _cache_set(domain, answers, TTL_GAME)
            return {"domain": domain, "type": "game", "answers": answers, "ttl": TTL_GAME}

    # Fallback: resolve via the main DNS resolver
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        # Build DNS query for A record
        tid = 0x1234
        qname = b""
        for part in domain.split("."):
            qname += bytes([len(part)]) + part.encode()
        qname += b"\x00"
        header = struct.pack(">6H", tid, 0x0100, 1, 0, 0, 0)
        query = header + qname + struct.pack(">HH", 1, 1)
        sock.sendto(query, ("127.0.0.1", 53))
        resp, _ = sock.recvfrom(4096)
        sock.close()
        # Parse response
        if len(resp) >= 12:
            tid_r, flags, qdcount, ancount = struct.unpack(">4H", resp[:8])
            if flags & 0x8000 and ancount > 0:
                pos = 12 + len(qname) + 4
                answers = []
                for _ in range(ancount):
                    if resp[pos] & 0xC0 == 0xC0:
                        pos += 2
                    else:
                        while resp[pos] != 0:
                            pos += resp[pos] + 1
                        pos += 1
                    pos += 4
                    rtype, rclass, _, rdlength = struct.unpack(">4H", resp[pos:pos+8])
                    pos += 10
                    if rtype == 1 and rdlength == 4:  # A record
                        ip = ".".join(str(b) for b in resp[pos:pos+4])
                        answers.append(ip)
                    pos += rdlength
                if answers:
                    _cache_set(domain, answers, TTL_GAME)
                    return {"domain": domain, "type": "game", "answers": answers, "ttl": TTL_GAME}
    except Exception:
        pass

    return {"domain": domain, "type": "game", "answers": [], "ttl": 0,
            "error": "game domain not in database"}

def get_game_list() -> list:
    """Return the list of supported game domains."""
    return [{"domain": d, "ip": ip} for d, ip in GAME_DOMAINS.items()]

# ---------------------------------------------------------------------------
# HTTP API
# ---------------------------------------------------------------------------
def start_api():
    """Start the Gaming DNS API on port 8087."""
    import http.server

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/api/gaming/resolve"):
                qs = urllib.parse.urlparse(self.path).query
                params = urllib.parse.parse_qs(qs)
                domain = params.get("name", [None])[0]
                if not domain:
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "missing name parameter"}).encode())
                    return
                result = resolve_game(domain)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(result, indent=2).encode())

            elif self.path == "/api/gaming/list":
                games = get_game_list()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"games": games, "count": len(games)}).encode())

            elif self.path == "/health":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ok", "port": 8087, "version": VERSION}).encode())
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format, *args):
            pass

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 8087), Handler)
    print(f"[gaming-dns v{VERSION}] API on :8087", flush=True)
    server.serve_forever()

if __name__ == "__main__":
    start_api()