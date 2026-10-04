#!/usr/bin/env python3
"""
SOURAN AI NETWORK SERVER v4.2.0 — Learning Engine
File: souran_learning_engine.py  |  Port: 8084

Active learning daemon that monitors DNS resolution patterns,
tracks censorship events, and adapts resolution strategies.

Behaviours:
  - Polls the DoH front-end health endpoint every 30s
  - Reads Unbound stats via unbound-control
  - Tracks resolution latency, fallback usage, poison events
  - Learns optimal DoH endpoint ordering by success rate
  - Adapts cache TTLs based on domain popularity
  - Persists learning state to disk (survives restarts)
  - Exposes /api/learn/* API for the 8082 dashboard

Design: pure stdlib (no pip deps), runs as a systemd service.
"""

import json, os, socket, subprocess, sys, threading, time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.0.0"
STATE_FILE = Path("/opt/souran-ai/data/learning-engine.json")
HEALTH_URL = "http://127.0.0.1:54/health"
UNBOUND_CONF = "/opt/souran-ai/config/souran-unbound.conf.yaml"

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
state = {
    "version": VERSION,
    "updated_at": None,
    "uptime_seconds": 0,
    "cycles": 0,

    # Resolution tracking
    "resolution": {
        "total_queries": 0,
        "tier1_hits": 0,
        "tier2_hits": 0,
        "poison_blocked": 0,
        "failures": 0,
        "latencies_ms": [],          # last 200 samples
        "top_domains": Counter(),    # domain -> count
    },

    # DoH endpoint learning
    "doh_endpoints": {
        "https://cloudflare-dns.com/dns-query": {"success": 0, "fail": 0, "latency_ms": []},
        "https://dns.google/resolve":          {"success": 0, "fail": 0, "latency_ms": []},
    },
    "doh_best_endpoint": None,

    # Censorship tracking
    "censorship": {
        "poisoned_answers": 0,
        "censored_names_blocked": [],   # last 200
        "first_seen": {},               # domain -> timestamp
        "blocked_by_tier": {"tier1": 0, "tier2": 0},
    },

    # Cache intelligence
    "cache": {
        "hit_rate_history": [],         # last 100 samples
        "recommended_ttl": 300,
        "prefetch_candidates": [],
    },

    # Circuit health
    "circuits": {
        "unbound": {"ok": True, "failures": 0, "last_check": None},
        "doh_fallback": {"ok": True, "failures": 0, "last_check": None},
        "tor": {"ok": True, "failures": 0, "last_check": None},
    },
}

_state_lock = threading.Lock()
_running = True
_started_at = time.time()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _http_get(url, timeout=5):
    try:
        import urllib.request
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None


def _unbound_stats():
    try:
        rc, out, _ = subprocess.run(
            ["unbound-control", "-c", UNBOUND_CONF, "stats_noreset"],
            capture_output=True, text=True, timeout=5,
        ).returncode, None, None
        # Re-run to get output
        p = subprocess.run(
            ["unbound-control", "-c", UNBOUND_CONF, "stats_noreset"],
            capture_output=True, text=True, timeout=5,
        )
        if p.returncode != 0:
            return None
        stats = {}
        for line in p.stdout.strip().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                try:
                    stats[k.strip()] = int(v.strip())
                except ValueError:
                    pass
        return stats
    except Exception:
        return None


def _read_health():
    return _http_get(HEALTH_URL, timeout=3)


# ---------------------------------------------------------------------------
# Learning loops
# ---------------------------------------------------------------------------
def _learn_resolution(health):
    """Update resolution stats from health endpoint."""
    if not health:
        return
    stats = health.get("stats", {})
    resolver = health.get("resolver", {})

    with _state_lock:
        s = state["resolution"]
        s["total_queries"] += 1
        s["tier1_hits"] = stats.get("primary", 0)
        s["tier2_hits"] = stats.get("fallback", 0)
        s["poison_blocked"] = stats.get("poisoned", 0)
        s["failures"] = stats.get("fail", 0)

        # Track circuits
        rh = resolver.get("resolver_health", {})
        level = rh.get("level", "unknown")
        state["circuits"]["unbound"]["ok"] = level != "critical"
        state["circuits"]["doh_fallback"]["ok"] = level != "critical"

        state["updated_at"] = datetime.now(timezone.utc).isoformat()
        state["cycles"] += 1


def _learn_doh_performance():
    """Probe each DoH endpoint and record latency/success."""
    endpoints = list(state["doh_endpoints"].keys())
    for url in endpoints:
        t0 = time.time()
        try:
            import urllib.request
            host = url.split("/")[2]
            target = f"{url}?name=example.com&type=A"
            req = urllib.request.Request(target, headers={"accept": "application/dns-json"})
            with urllib.request.urlopen(req, timeout=8) as r:
                doc = json.loads(r.read().decode("utf-8", "replace"))
            elapsed = (time.time() - t0) * 1000
            if doc.get("Status") == 0 and doc.get("Answer"):
                with _state_lock:
                    ep = state["doh_endpoints"][url]
                    ep["success"] += 1
                    ep["latency_ms"].append(round(elapsed, 1))
                    if len(ep["latency_ms"]) > 200:
                        ep["latency_ms"] = ep["latency_ms"][-200:]
            else:
                with _state_lock:
                    state["doh_endpoints"][url]["fail"] += 1
        except Exception:
            with _state_lock:
                state["doh_endpoints"][url]["fail"] += 1

    # Pick best endpoint by success rate
    with _state_lock:
        best = None
        best_rate = -1
        for url, ep in state["doh_endpoints"].items():
            total = ep["success"] + ep["fail"]
            rate = ep["success"] / total if total > 0 else 0
            if rate > best_rate:
                best_rate = rate
                best = url
        state["doh_best_endpoint"] = best


def _learn_cache_intelligence():
    """Recommend cache TTL based on hit rate trend."""
    unbound_stats = _unbound_stats()
    if not unbound_stats:
        return
    with _state_lock:
        hits = unbound_stats.get("thread0.num.cachehits", 0)
        misses = unbound_stats.get("thread0.num.cachemiss", 0)
        total = hits + misses
        rate = hits / total if total > 0 else 0
        history = state["cache"]["hit_rate_history"]
        history.append(round(rate, 3))
        if len(history) > 100:
            history.pop(0)

        # If hit rate is dropping, increase TTL to keep more entries
        # If hit rate is high and stable, reduce TTL for fresher data
        avg_rate = sum(history[-20:]) / len(history[-20:]) if len(history) >= 20 else rate
        if avg_rate < 0.5:
            state["cache"]["recommended_ttl"] = min(600, state["cache"]["recommended_ttl"] + 30)
        elif avg_rate > 0.9:
            state["cache"]["recommended_ttl"] = max(60, state["cache"]["recommended_ttl"] - 30)


def _learn_censorship(health):
    """Track censorship events — poisoned answers, blocked domains."""
    if not health:
        return
    stats = health.get("stats", {})
    poisoned = stats.get("poisoned", 0)
    with _state_lock:
        c = state["censorship"]
        c["poisoned_answers"] = poisoned
        if poisoned > 0:
            c["blocked_by_tier"]["tier2"] += 1


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
def _loop():
    global _running
    print(f"[learning-engine v{VERSION}] started", flush=True)
    while _running:
        try:
            health = _read_health()
            _learn_resolution(health)
            _learn_doh_performance()
            _learn_cache_intelligence()
            _learn_censorship(health)
            STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            with _state_lock:
                # deep-enough copy: `dict(state)` shares the nested dicts, so slicing
                # s["resolution"]["latencies_ms"] would mutate the live in-memory state.
                s = {**state, "resolution": dict(state["resolution"])}
                # top_domains is a Counter in memory but is persisted as a plain dict
                # (Counter is a dict subclass, so json round-trips it into a dict).
                # Re-wrap defensively every cycle so .most_common() is always available.
                s["resolution"]["top_domains"] = dict(
                    Counter(s["resolution"].get("top_domains") or {}).most_common(50)
                )
                s["resolution"]["latencies_ms"] = s["resolution"]["latencies_ms"][-200:]
                STATE_FILE.write_text(json.dumps(s, indent=2, default=str), encoding="utf-8")
        except Exception as e:
            print(f"[learning-engine] cycle error: {e}", flush=True)
        time.sleep(30)


# ---------------------------------------------------------------------------
# HTTP API
# ---------------------------------------------------------------------------
def start_api():
    """Start a minimal HTTP API on port 8084 for the dashboard."""
    import http.server

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path in ("/api/learn", "/api/learn/status"):
                with _state_lock:
                    body = json.dumps(dict(state), default=str, indent=2)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body.encode())
            elif self.path == "/api/learn/doh":
                with _state_lock:
                    body = json.dumps(state["doh_endpoints"], default=str, indent=2)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body.encode())
            elif self.path == "/api/learn/cache":
                with _state_lock:
                    body = json.dumps(state["cache"], default=str, indent=2)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body.encode())
            elif self.path == "/health":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ok", "port": 8084}).encode())
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, fmt, *args):
            pass  # quiet

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 8084), Handler)
    server.serve_forever()


# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------
def main():
    # Load persisted state
    if STATE_FILE.exists():
        try:
            loaded = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            with _state_lock:
                for k, v in loaded.items():
                    if k in state:
                        if k == "resolution" and isinstance(v, dict):
                            state["resolution"].update(v)
                            state["resolution"]["top_domains"] = Counter(v.get("top_domains", {}))
                            state["resolution"]["latencies_ms"] = v.get("latencies_ms", [])
                        else:
                            state[k] = v
        except Exception as e:
            print(f"[learning-engine] load state: {e}", flush=True)

    # Start API server in background
    api_thread = threading.Thread(target=start_api, daemon=True)
    api_thread.start()
    print(f"[learning-engine v{VERSION}] API on :8084", flush=True)

    # Run learning loop
    _loop()


if __name__ == "__main__":
    main()