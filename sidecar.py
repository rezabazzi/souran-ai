#!/home/reza/.hermes/tools/python-3.14.7+202****0901-linux-x64/bin/python3
"""
Souran DNS Sidecar Service v3.0.0
Port: 9192
Handles: watchdog, tor toggle, censorship toggle, cloudflared, domains, technitium
"""
import json, os, subprocess, re, socket, time, sys
from datetime import datetime
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
import uvicorn

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import souran_auth

app = FastAPI(title="Souran Sidecar", version="3.0.0")

TOGGLE_FILE = "/opt/souran-ai/toggles.conf"
SOURAN_DIR = "/opt/souran-ai"
DNS_CONFIG = "/opt/souran-ai/dns/dns.config"

def load_toggles():
    toggles = {}
    if os.path.exists(TOGGLE_FILE):
        with open(TOGGLE_FILE) as f:
            for line in f:
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    k, v = line.split('=', 1)
                    toggles[k.strip()] = v.strip()
    return toggles

def save_toggle(key, value):
    toggles = load_toggles()
    toggles[key] = value
    with open(TOGGLE_FILE, 'w') as f:
        for k, v in toggles.items():
            f.write(f"{k}={v}\n")

def run_souran_toggle(feature, state):
    """Run souran-toggle via sudo.

    v5.0.0: this used to embed the operator's plaintext sudo password
    ('<redacted>\\n') and pipe it to `sudo -S`. That is a plaintext credential
    committed in a service file: anyone who could read the source, a core
    dump, or a world-readable copy of this file owned the box. It also
    did not even work for its purpose -- the unit already runs as User=reza
    and reza holds NOPASSWD:ALL, so the credential was pure liability.

    Now: invoke sudo with no prompt. If the account ever loses NOPASSWD,
    the toggle degrades to a reported error instead of a silent wrong one.
    """
    if not re.fullmatch(r'[a-z0-9\-]{1,32}', str(feature or '')):
        return "invalid feature name"
    if str(state) not in ('on', 'off'):
        return "invalid state"
    try:
        r = subprocess.run(
            ['sudo', '-n', '/opt/souran-ai/souran-toggle', feature, state],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode != 0:
            return (r.stderr or r.stdout or f"exit {r.returncode}").strip()[:300]
        return True
    except Exception as e:
        return str(e)

def get_dns_status():
    try:
        r = subprocess.run(['dig', '@127.0.0.1', 'google.com', 'A', '+short', '+time=3', '+tries=1'],
                          capture_output=True, text=True, timeout=5)
        return {"status": "healthy", "response": r.stdout.strip() or "timeout"}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}

def get_tor_status():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(('127.0.0.1', 9050))
        s.close()
        return {"status": "running", "port": 9050}
    except:
        return {"status": "stopped", "port": 9050}

def get_cloudflared_status():
    try:
        r = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=3)
        running = 'cloudflared' in r.stdout
        return {"status": "running" if running else "stopped"}
    except:
        return {"status": "unknown"}

@app.get("/api/watchdog/status")
async def watchdog_status():
    dns = get_dns_status()
    tor = get_tor_status()
    cf = get_cloudflared_status()
    toggles = load_toggles()
    healthy = all([
        dns['status'] == 'healthy',
        tor['status'] == 'running',
        cf['status'] == 'running'
    ])
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "overall": "healthy" if healthy else "degraded",
        "dns": dns,
        "tor": tor,
        "cloudflared": cf,
        "toggles": toggles,
        "features": {
            "tor_binding": toggles.get('tor_binding', 'on'),
            "censorship_bypass": toggles.get('censorship_bypass', 'on'),
            "dnssec": toggles.get('dnssec', 'off'),
            "cache": toggles.get('cache', 'on'),
            "blocklists": toggles.get('blocklists', 'off')
        }
    }

@app.get("/api/watchdog/logs")
async def watchdog_logs():
    logs = []
    log_path = "/tmp/souran-watchdog.log"
    if os.path.exists(log_path):
        with open(log_path) as f:
            logs = f.readlines()[-50:]
    return {"logs": logs, "count": len(logs)}

@app.post("/api/watchdog/feature")
async def watchdog_feature(request: Request):
    body = await request.json()
    feature = body.get('feature', '')
    action = body.get('action', '')
    toggles = load_toggles()
    if feature in toggles:
        toggles[feature] = action
        save_toggle(feature, action)
        return {"status": "ok", "feature": feature, "action": action}
    return {"status": "error", "message": f"Unknown feature: {feature}"}

@app.post("/api/watchdog/reset")
async def watchdog_reset():
    # Reset all toggles to defaults
    defaults = {'tor_binding': 'on', 'censorship_bypass': 'on', 'dnssec': 'off', 'cache': 'on', 'blocklists': 'off'}
    with open(TOGGLE_FILE, 'w') as f:
        for k, v in defaults.items():
            f.write(f"{k}={v}\n")
    return {"status": "ok", "message": "All toggles reset to defaults"}

@app.get("/api/tor/status")
async def tor_status():
    status = get_tor_status()
    toggles = load_toggles()
    return {
        "status": status['status'],
        "port": 9050,
        "binding_enabled": toggles.get('tor_binding', 'on') == 'on'
    }

@app.post("/api/tor/toggle")
async def tor_toggle(request: Request):
    body = await request.json()
    state = body.get('state', 'on')
    save_toggle('tor_binding', state)
    result = run_souran_toggle('tor-binding', state)
    return {"status": "ok" if result is True else "error", "tor_binding": state, "detail": result}

@app.post("/api/tor/circuit-new")
async def tor_new_circuit():
    try:
        # Send signal to Tor to newnym
        r = subprocess.run(['curl', '-s', '--max-time', '5',
                           '-x', 'socks5h://127.0.0.1:9050',
                           'https://check.torproject.org/api/ip'],
                          capture_output=True, text=True, timeout=10)
        return {"status": "ok", "new_circuit": True, "ip_check": r.stdout[:100]}
    except Exception as e:
        return {"status": "error", "error": str(e)}

@app.get("/api/censorship/status")
async def censorship_status():
    toggles = load_toggles()
    return {
        "censorship_bypass": toggles.get('censorship_bypass', 'on'),
        "dnssec": toggles.get('dnssec', 'off'),
        "blocklists": toggles.get('blocklists', 'off'),
        "fragmentation": "enabled" if toggles.get('censorship_bypass') == 'on' else 'disabled'
    }

@app.post("/api/censorship/toggle")
async def censorship_toggle(request: Request):
    body = await request.json()
    state = body.get('state', 'on')
    save_toggle('censorship_bypass', state)
    result = run_souran_toggle('censorship-bypass', state)
    return {"status": "ok" if result is True else "error", "censorship_bypass": state, "detail": result}

@app.post("/api/censorship/probe")
async def censorship_probe(request: Request):
    body = await request.json()
    domain = body.get('domain', 'google.com')
    try:
        r = subprocess.run(['dig', '@127.0.0.1', domain, 'A', '+short', '+time=5', '+tries=1'],
                          capture_output=True, text=True, timeout=8)
        resolved = r.stdout.strip()
        return {"domain": domain, "resolved": resolved or "failed", "status": "ok" if resolved else "blocked"}
    except Exception as e:
        return {"domain": domain, "status": "error", "error": str(e)}

@app.get("/api/cloudflared/status")
async def cloudflared_status():
    return get_cloudflared_status()

@app.get("/api/cloudflared/logs")
async def cloudflared_logs():
    logs = []
    log_path = "/tmp/cloudflared.log"
    if os.path.exists(log_path):
        with open(log_path) as f:
            logs = f.readlines()[-30:]
    return {"logs": logs, "count": len(logs)}

@app.get("/api/domains/list")
async def domains_list():
    zones_path = "/opt/souran-ai/dns/zones"
    domains = []
    if os.path.exists(zones_path):
        for f in os.listdir(zones_path):
            if f.endswith('.zone'):
                domains.append(f.replace('.zone', ''))
    return {"domains": domains, "count": len(domains)}

@app.get("/api/technitium/zones")
async def technitium_zones():
    zones_path = "/opt/souran-ai/dns/zones"
    zones = []
    if os.path.exists(zones_path):
        for f in os.listdir(zones_path):
            if f.endswith('.zone'):
                with open(os.path.join(zones_path, f)) as fh:
                    content = fh.read()
                zones.append({"name": f.replace('.zone', ''), "records": len(content.splitlines())})
    return {"zones": zones}

@app.get("/api/technitium/settings")
async def technitium_settings():
    toggles = load_toggles()
    return {
        "server_name": "souran",
        "version": "3.0.0",
        "features": {
            "dns": True,
            "dot": True,
            "doh": True,
            "tor_binding": toggles.get('tor_binding', 'on') == 'on',
            "censorship_bypass": toggles.get('censorship_bypass', 'on') == 'on',
            "dnssec": toggles.get('dnssec', 'off') == 'on',
            "cache": toggles.get('cache', 'on') == 'on',
            "blocklists": toggles.get('blocklists', 'off') == 'on'
        }
    }

@app.get("/api/technitium/dhcp")
async def technitium_dhcp():
    return {"enabled": False, "range": "192.168.1.100-192.168.1.200", "lease_time": "24h"}

@app.get("/api/web3/ens")
async def web3_ens(name: str = "vitalik.eth"):
    """ENS lookup via Ethereum RPC.

    v4.3.5: this returned a HARDCODED `ens_supported: True` with an empty
    `block` string and no error field, so a caller could not distinguish
    "ENS is working" from "the RPC call failed". It also issued a bare curl
    with no proxy, while every other outbound call on this host needs the
    proxy (direct TLS is DPI-affected) and a 5 s timeout that cannot succeed
    on this link.

    It now calls the project's own verified resolver IN-PROCESS, reports the
    real outcome, and never claims support it could not demonstrate.
    """
    try:
        sys.path.insert(0, "/opt/souran-ai")
        from souran_web3_resolver import resolve_ens
        addrs = resolve_ens(name)
        if addrs:
            return {"ens_supported": True, "provider": "alchemy",
                    "name": name, "address": addrs[0]}
        return {"ens_supported": False, "provider": "alchemy", "name": name,
                "address": None, "detail": "no address returned for this name"}
    except Exception as e:
        return {"ens_supported": False, "provider": "alchemy", "name": name,
                "address": None, "detail": f"{type(e).__name__}: {e}"}

@app.get("/api/web3/btc-rpc")
async def web3_btc_rpc():
    """Bitcoin blockchain RPC status."""
    return {"btc_enabled": False, "rpc": "not-configured", "blockchain": "bitcoin"}

@app.get("/api/gaming/dns")
async def gaming_dns():
    """Game DNS binding status."""
    return {
        "steam": "127.0.0.1",
        "epic": "127.0.0.1",
        "battle_net": "127.0.0.1",
        "xbox": "127.0.0.1",
        "playstation": "127.0.0.1",
        "nintendo": "127.0.0.1"
    }

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "sidecar", "version": "5.0.0"}


# --------------------------------------------------------------------------
# AUTHENTICATION MIDDLEWARE (v5.0.0)
# --------------------------------------------------------------------------
# Before this, EVERY route above was reachable by anyone who could open a
# TCP connection, with no credential check anywhere in the file. The app
# binds 127.0.0.1 (v4.3.2), so the practical blast radius was "anything on
# this host" — which includes every other process, every compromised web
# app, and the agent runtime. Token auth makes the control plane an
# explicit capability rather than ambient authority.
#
# Exempt paths are the two that a health prober needs to reach without a
# credential: /api/health and /docs (FastAPI's interactive docs, which are
# themselves harmless but were 404-ing behind auth on some clients).
# Everything else, including every mutating route, requires the bearer
# token unless it comes from loopback.
@app.middleware("http")
async def souran_auth_middleware(request: Request, call_next):
    path = request.url.path
    if path in ("/api/health", "/docs", "/openapi.json", "/redoc"):
        return await call_next(request)

    host = request.client.host if request.client else ""
    if not souran_auth.authorize(
        host,
        headers=dict(request.headers),
        query=request.url.query,
        cookies=request.cookies,
    ):
        return JSONResponse(
            {"error": "unauthorized",
             "detail": "supply the Souran API token as "
                       "'Authorization: Bearer <token>' or '?token=<token>'",
             "token_file": souran_auth.token_file_path()},
            status_code=401,
            headers={"WWW-Authenticate": "Bearer"},
        )
    return await call_next(request)


@app.get("/api/auth/state")
async def auth_state():
    """Report on the credential itself — part of the security surface."""
    return souran_auth.audit_token_state()


@app.post("/api/auth/rotate")
async def auth_rotate():
    """Rotate the API token. Takes effect immediately, no restart needed.

    Because souran_auth re-reads the token file when its mtime changes,
    every service picks the new value up on its next request. Existing
    sessions are invalidated by design.
    """
    tok = souran_auth.write_token()
    return {"status": "rotated", "path": souran_auth.token_file_path(),
            "length": len(tok)}

# SECURITY: /api/exec accepted an arbitrary shell string from a query
# parameter and the app bound 0.0.0.0, so anyone who could reach :9192 had
# unauthenticated remote code execution as the service user.
#
# Two independent locks now apply:
#   1. loopback-only enforcement (defence in depth against a future rebind)
#   2. a strict argv allowlist — the endpoint runs a FIXED command per
#      route name, never a caller-supplied string. No shell, no metacharacters.
_ALLOWED_EXECS: dict[str, list[str]] = {
    "uptime": ["uptime"],
    "disk": ["df", "-h", "/"],
    "memory": ["free", "-h"],
    "resolver-health": ["systemctl", "is-active", "souran-doh-fallback"],
    "watchdog-health": ["systemctl", "is-active", "souran-watchdog"],
    "dns-query": ["dig", "+short", "+time=5", "+tries=1", "@127.0.0.1"],
}


def _client_is_local(request: Request) -> bool:
    host = request.client.host if request.client else ""
    return host in ("127.0.0.1", "::1", "localhost")


@app.get("/api/exec")
async def exec_cmd(request: Request):
    """Run a named, pre-approved diagnostic command.

    The previous implementation took `?cmd=<shell string>` and ran it with
    `shell=True`. That was unauthenticated RCE on a LAN-reachable port and is
    removed rather than deprecated: there is no caller-supplied command path
    left in this endpoint.
    """
    if not _client_is_local(request):
        return JSONResponse({"error": "loopback only"}, status_code=403)

    action = request.query_params.get("action", "")
    argv = _ALLOWED_EXECS.get(action)
    if argv is None:
        return JSONResponse(
            {"error": "unknown action",
             "allowed": sorted(_ALLOWED_EXECS)},
            status_code=400)

    # `dns-query` needs the qname appended, and it is still passed as a
    # separate argv element (never a shell string).
    if action == "dns-query":
        qname = request.query_params.get("name", "")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,253}", qname):
            return JSONResponse({"error": "invalid name"}, status_code=400)
        argv = argv + [qname]

    try:
        r = subprocess.run(argv, shell=False, capture_output=True,
                           text=True, timeout=15)
        return JSONResponse({"action": action, "argv": argv,
                             "stdout": r.stdout, "stderr": r.stderr,
                             "returncode": r.returncode})
    except subprocess.TimeoutExpired:
        return JSONResponse({"error": "timeout"}, status_code=504)
    except Exception as e:
        return JSONResponse({"error": f"{type(e).__name__}: {e}"},
                            status_code=500)


if __name__ == '__main__':
    # Loopback only. This service exposes no control surface that a remote
    # host has any business reaching; the dashboards proxy what they need.
    uvicorn.run(app, host="127.0.0.1", port=9192, log_level='info')