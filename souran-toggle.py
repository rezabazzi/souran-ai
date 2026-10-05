#!/usr/bin/env python3
"""
SOURAN AI NETWORK SERVER v4.2.1 — Feature Toggle Manager
File: souran-toggle.py  |  Port: 8082 (via dashboard API)

Manages on/off state for all Souran features.
Persists state to /opt/souran-ai/data/toggles.json.
"""

import json, os, subprocess, sys, time
from pathlib import Path

STATE_FILE = Path("/opt/souran-ai/data/toggles.json")

FEATURES = {
    "dns":        {"port": 53,    "service": "souran-dns",        "label": "DNS Resolver"},
    "dot":        {"port": 853,   "service": "souran-dns-dot",     "label": "DNS over TLS"},
    "doh":        {"port": 8083,  "service": "souran-8083-doh",    "label": "DNS over HTTPS"},
    "tor":        {"port": 9050,  "service": "tor@default",        "label": "Tor SOCKS"},
    "web3":       {"port": 8086,  "service": "souran-web3-resolver","label": "Web3 DNS"},
    "gaming":     {"port": 8087,  "service": "souran-gaming-dns",  "label": "Gaming DNS"},
    "censorship": {"port": None,  "service": "souran-zapret",      "label": "Censorship Bypass"},
    "learning":   {"port": 8084,  "service": "souran-learning-engine","label": "Learning Engine"},
    "anticompress":{"port": 8085, "service": "souran-anticompress", "label": "Anti-Compress"},
    "dashboard":  {"port": 8082,  "service": "souran-8082-dashboard","label": "Agent Dashboard"},
    "neuro":      {"port": 8383,  "service": "souran-web-8383",    "label": "Neuro Dashboard"},
    "watchdog":   {"port": 53443, "service": "souran-watchdog",    "label": "Watchdog"},
}

def _load():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    # Default: all ON
    return {f: True for f in FEATURES}

def _save(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))

def get_state():
    return _load()

def set_feature(name, enabled):
    state = _load()
    if name not in FEATURES:
        return {"error": f"unknown feature: {name}"}
    state[name] = bool(enabled)
    _save(state)
    # Apply immediately via systemd
    svc = FEATURES[name]["service"]
    if enabled:
        subprocess.run(["sudo", "-n", "systemctl", "restart", svc],
                        timeout=10, capture_output=True)
    else:
        subprocess.run(["sudo", "-n", "systemctl", "stop", svc],
                        timeout=10, capture_output=True)
    return {"feature": name, "enabled": state[name], "service": svc}

def set_all(enabled):
    """Turn all features on or off."""
    results = {}
    for name in FEATURES:
        r = set_feature(name, enabled)
        results[name] = r
    return {"all": enabled, "results": results}

def status():
    """Get current toggle state + live service status."""
    state = _load()
    out = {}
    for name, info in FEATURES.items():
        svc = info["service"]
        live = False
        try:
            r = subprocess.run(["systemctl", "is-active", svc],
                               capture_output=True, text=True, timeout=5)
            live = r.stdout.strip() == "active"
        except Exception:
            pass
        out[name] = {
            "configured": state.get(name, True),
            "live": live,
            "port": info["port"],
            "service": svc,
            "label": info["label"],
        }
    return out

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "status":
        print(json.dumps(status(), indent=2))
    elif cmd == "set" and len(sys.argv) > 3:
        print(json.dumps(set_feature(sys.argv[2], sys.argv[3] == "true"), indent=2))
    elif cmd == "all" and len(sys.argv) > 2:
        print(json.dumps(set_all(sys.argv[2] == "true"), indent=2))
    else:
        print(f"Usage: {sys.argv[0]} status|set <feature> <true|false>|all <true|false>")