#!/usr/bin/env python3
"""
SOURAN AI NETWORK SERVER v5.0.0 — Neuro Dashboard
Port: 8383 | File: web-dashboard-8383.py

REPLACES the v5.2.0 mock (backed up as web-dashboard-8383.py.v5.2.0-mock.bak).
That version returned hardcoded numbers: 12,847 queries, an 87.3% cache-hit
rate, fabricated "logs" dated 2026-09-30, and invented zones. It looked
plausible and was entirely fictional — which is how a dead resolver keeps
looking healthy.

Every figure here comes from souran_telemetry.py, which reads this host.
Where a source is unavailable the API reports "unavailable" rather than
inventing a value. No external assets: the UI works offline, on a link
where CDNs are unreliable.
"""
from __future__ import annotations

import os
import subprocess
import sys
import json
from datetime import datetime

sys.path.insert(0, "/opt/souran-ai")

from fastapi import FastAPI, HTTPException, Query, Request, Body
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

import souran_telemetry as tel

app = FastAPI(title="Souran Neuro Dashboard", version="5.0.0",
              docs_url="/api/docs", redoc_url=None)

# Live resolution events for the activity feed.
_EVENTS: list = []
_MAX_EVENTS = 200


def _record(event: str, details: str, ok: bool = True) -> None:
    _EVENTS.insert(0, {
        "time": datetime.now().astimezone().isoformat(timespec="seconds"),
        "event": event,
        "details": details,
        "ok": ok,
    })
    del _EVENTS[_MAX_EVENTS:]


def _resolver_verdict(snap: dict) -> dict:
    """Turn counters into an honest verdict.

    A high poison count is NOT a failure — it is the censor being caught.
    The real failure signals are: names unresolved by any tier, and a
    missing resolver NAT exemption.
    """
    res = snap.get("resolver", {})
    stats = res.get("stats", {}) if res.get("available") else {}
    poisoned = stats.get("poisoned", 0)
    failed = stats.get("fail", 0)
    served = stats.get("primary", 0) + stats.get("fallback", 0)
    total = served + failed
    if not res.get("available"):
        return {"level": "critical", "reason": "resolver tier unreachable",
                "total": 0}
    if total and failed / total > 0.25:
        return {"level": "critical",
                "reason": f"{failed}/{total} queries failed to resolve",
                "total": total}
    if not snap.get("egress", {}).get("resolver_bypass_ok", False):
        return {"level": "critical",
                "reason": "resolver NAT exemption missing — DNS will die",
                "total": total}
    return {
        "level": "healthy",
        "reason": (f"{poisoned} injected answers intercepted and refused"
                   if poisoned else "no injection seen"),
        "total": total,
        "poisoned_blocked": poisoned,
        "failed": failed,
        "tier1": stats.get("primary", 0),
        "tier2_doh": stats.get("fallback", 0),
    }


# ---------------------------------------------------------------------------
# API — all values live
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    res = tel.resolver_health()
    return JSONResponse({
        "status": "ok" if res.get("available") else "degraded",
        "port": 8383,
        "service": "souran-web-dashboard",
        "version": "5.0.0",
        "resolver_available": res.get("available", False),
        "data_source": "live",
    })


@app.get("/api/status")
async def api_status():
    snap = tel.snapshot()
    snap["resolver_health"] = _resolver_verdict(snap)
    return JSONResponse(snap)


@app.get("/api/stats")
async def api_stats():
    res = tel.resolver_health()
    if not res.get("available"):
        return JSONResponse({"available": False,
                             "error": res.get("error", "unavailable")},
                            status_code=503)
    stats = res.get("stats", {})
    unbound = tel.unbound_stats()
    hit_rate = None
    if unbound.get("available"):
        hits, miss = unbound["cache_hits"], unbound["cache_miss"]
        if hits + miss:
            hit_rate = round(100.0 * hits / (hits + miss), 1)
    return JSONResponse({
        "available": True,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "total_queries": sum(v for v in stats.values() if isinstance(v, int)),
        "cache_entries": res.get("cache_entries", 0),
        "tier1_iterative": stats.get("primary", 0),
        "tier2_doh": stats.get("fallback", 0),
        "poisoned_blocked": stats.get("poisoned", 0),
        "failed": stats.get("fail", 0),
        "cache_hit_rate_pct": hit_rate,
        "unbound": unbound,
        "data_source": "live — no synthetic values",
    })


@app.get("/api/services")
async def api_services():
    return JSONResponse({"services": tel.services()})


@app.get("/api/ports")
async def api_ports():
    return JSONResponse({"listeners": tel.listeners()})


@app.get("/api/egress")
async def api_egress():
    return JSONResponse(tel.egress_rules())


@app.get("/api/bypass")
async def api_bypass():
    return JSONResponse(tel.bypass_stack())


@app.get("/api/probe")
async def api_probe(count: int = 5):
    if count < 1 or count > 7:
        raise HTTPException(400, "count must be 1..7")
    results = tel.probe(count)
    for r in results:
        _record("Resolution probe",
                f"{r['domain']} -> {', '.join(r['answers']) or r['status']}",
                r["ok"])
    good = sum(1 for r in results if r["ok"])
    return JSONResponse({
        "results": results,
        "passed": good,
        "total": len(results),
        "poison_free": all(not tel.is_poisonable_answer(r["answers"])
                           for r in results),
    })


@app.get("/api/events")
async def api_events(limit: int = 50):
    return JSONResponse({"events": _EVENTS[:max(1, min(limit, _MAX_EVENTS))],
                         "note": "live since dashboard start"})


@app.get("/api/telemetry")
async def api_telemetry():
    return JSONResponse(tel.snapshot())


@app.get("/api/zones")
async def api_zones():
    """Real zone files read from disk — not invented."""
    zones: list = []
    for root in ("/etc/bind", "/opt/souran-ai/dns/zones",
                 "/opt/souran-ai/engine/unbound/etc"):
        if not os.path.isdir(root):
            continue
        try:
            for name in sorted(os.listdir(root)):
                if name.endswith((".zone", ".db", ".conf", ".yaml")):
                    path = os.path.join(root, name)
                    try:
                        size = os.path.getsize(path)
                    except OSError:
                        size = 0
                    zones.append({"name": name, "path": path,
                                  "bytes": size, "source": "disk"})
        except OSError:
            continue
    return JSONResponse({
        "zones": zones,
        "count": len(zones),
        "note": "read from disk; the previous build invented these",
    })


# ---------------------------------------------------------------------------
# v4.3 — record-type resolution matrix
# ---------------------------------------------------------------------------
@app.get("/api/rrtypes")
async def api_rrtypes(name: str = Query("google.com"),
                      types: str = Query("A,AAAA,MX,TXT,NS,SOA,CNAME,HTTPS")):
    """Resolve a name across record types through the live :53 front-end.

    v4.2.1 only ever resolved A/AAAA, so this endpoint is what makes the
    general RR support (souran_dns_rr.py) visible and testable from the UI.
    Each type is probed with a real DNS query; a type that returns nothing is
    reported as such rather than being padded with a placeholder.
    """
    import socket
    import struct
    import time

    TYPE_MAP = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15,
                "TXT": 16, "AAAA": 28, "SRV": 33, "HTTPS": 65, "CAA": 257,
                "DNSKEY": 48, "DS": 43}
    wanted = [t.strip().upper() for t in types.split(",") if t.strip().upper()
              in TYPE_MAP]
    if not wanted:
        raise HTTPException(400, "no supported types requested")

    def _query(qname: str, qtype: int, tcp: bool = False):
        q = struct.pack("!HHHHHH", 0x5355, 0x0100, 1, 0, 0, 0)
        for label in qname.rstrip(".").split("."):
            if label:
                q += bytes([len(label)]) + label.encode("idna")
        q += b"\x00" + struct.pack("!HH", qtype, 1)
        try:
            if tcp:
                with socket.create_connection(("127.0.0.1", 53), timeout=20) as s:
                    s.settimeout(20)
                    s.sendall(struct.pack("!H", len(q)) + q)
                    ln = s.recv(2)
                    if len(ln) < 2:
                        return None
                    (n,) = struct.unpack("!H", ln)
                    buf = b""
                    while len(buf) < n:
                        chunk = s.recv(n - len(buf))
                        if not chunk:
                            break
                        buf += chunk
                    return buf or None
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(20)
                s.sendto(q, ("127.0.0.1", 53))
                data, _ = s.recvfrom(65535)
                return data
        except (socket.timeout, OSError):
            return None

    results = []
    for tname in wanted:
        qtype = TYPE_MAP[tname]
        started = time.time()
        pkt = _query(name, qtype)
        used_tcp = False
        # NOERROR + TC means "retry over TCP", per RFC 1035 §4.1.1.
        if pkt and len(pkt) >= 12:
            _qid, flags, _qd, an, _ns, _ar = struct.unpack("!HHHHHH", pkt[:12])
            if (flags & 0x0F) == 0 and (flags & 0x0200):
                pkt = _query(name, qtype, tcp=True)
                used_tcp = True
        entry = {"type": tname, "ok": False, "count": 0,
                 "records": [], "ms": None, "transport": "udp"}
        if pkt and len(pkt) >= 12:
            _qid, flags, _qd, an, _ns, _ar = struct.unpack("!HHHHHH", pkt[:12])
            rcode = flags & 0x0F
            entry["rcode"] = rcode
            entry["transport"] = "tcp" if used_tcp else "udp"
            entry["ms"] = round((time.time() - started) * 1000, 1)
            if rcode == 0 and an:
                entry["ok"] = True
                entry["count"] = an
                try:
                    sys.path.insert(0, "/opt/souran-ai")
                    from souran_dns_rr import iter_answers
                    entry["records"] = [
                        {"type": rt, "rdata_len": len(rd)}
                        for rt, rd, _ttl in iter_answers(pkt)
                    ]
                except Exception as exc:   # never fake records on a parse error
                    entry["records"] = []
                    entry["parse_error"] = str(exc)
        results.append(entry)

    resolved = sum(1 for r in results if r["ok"])
    return JSONResponse({
        "name": name,
        "results": results,
        "resolved": resolved,
        "requested": len(results),
        "support": "general RR passthrough (souran_dns_rr.py v4.3)",
        "data_source": "live queries to 127.0.0.1:53",
    })


# ---------------------------------------------------------------------------
# Feature toggles — on/off for all features
# ---------------------------------------------------------------------------
@app.get("/api/toggles")
async def api_toggles():
    """RETIRED -- returns the registry's summary.

    Used to shell out to souran-toggle.py and return the 12-key legacy
    store. That store and souran_features.py describe the same 31
    capabilities under different names, so they could never agree.
    """
    return await _sidecar("GET", "/api/features/summary/categories",
                          timeout=45)


@app.post("/api/toggle/{feature}")
async def api_toggle(feature: str, enabled: bool = Query(..., alias="enabled"), request: Request = None):
    """RETIRED -- delegates to the feature registry.

    This used to write a second, competing toggle store via
    souran-toggle.py (12 legacy keys in data/toggles.json) that shared no
    state with souran_features.py's 31 features. Two stores for the same
    concept drift by construction: the legacy key "dns" and the registry
    id "dns_recursive" are the same unit under different names.

    It also shelled out with `sudo -S`, which reads a password from stdin
    where nothing supplied one -- so the escalation could only ever fail.

    Kept as a route so an already-open page gets a clear message instead
    of a 404, and it delegates rather than maintaining its own state.
    """
    client = request.client.host if request else ""
    if client not in ("127.0.0.1", "::1"):
        raise HTTPException(403, "loopback only")
    return await _sidecar(
        "POST", f"/api/features/{feature}",
        {"state": "on" if enabled else "off"}, timeout=90)

@app.post("/api/toggles")
async def api_toggles_all(enabled: bool = Query(..., alias="enabled"), request: Request = None):
    """RETIRED -- "all on/off" now walks the registry.

    The legacy implementation restarted every Souran unit at once,
    including BOTH dashboards -- so pressing "all on" killed the UI that
    sent the request mid-flight and returned nothing.

    Now each feature goes through the registry's intent queue, one at a
    time, and the response reports per-feature results including any that
    did not take. A bulk action that reports its own failures is useful;
    one that silently drops the response is not.
    """
    _loopback(request)
    state = "on" if enabled else "off"

    import urllib.request as _ur
    opener = _ur.build_opener(_ur.ProxyHandler({}))
    try:
        with opener.open(SIDECAR + "/api/features/summary/categories",
                         timeout=45) as r:
            doc = json.loads(r.read().decode())
    except Exception as e:
        return JSONResponse({"error": f"{type(e).__name__}: {e}"[:300]},
                            status_code=502)

    done, failed = [], []
    for cat in (doc.get("categories") or {}).values():
        for f in cat:
            # Informational features have no actuator; asking is pointless.
            if not f.get("controllable"):
                continue
            try:
                req = _ur.Request(
                    f"{SIDECAR}/api/features/{f['id']}",
                    data=json.dumps({"state": state}).encode(),
                    method="POST",
                    headers={"Content-Type": "application/json"})
                with opener.open(req, timeout=90) as r:
                    res = json.loads(r.read().decode())
                (done if res.get("ok") else failed).append(f["id"])
            except Exception as e:
                failed.append(f"{f['id']} ({type(e).__name__})")

    _record("Toggle all", f"{state}: {len(done)} ok, {len(failed)} failed",
            not failed)
    return JSONResponse({"state": state, "ok": len(failed) == 0,
                         "applied": done, "failed": failed})


# =========================================================================
#  FEATURE REGISTRY PASSTHROUGH
# =========================================================================
# 8383 was showing a SECOND, COMPETING toggle store: souran-toggle.py,
# a legacy 12-key file (dns, dot, doh, tor, web3, gaming, censorship,
# learning, anticompress, dashboard, neuro, watchdog) in
# data/toggles.json. It never touched :9192 or souran_features.py.
#
# Two stores for the same concept cannot both be right: souran-toggle.py
# "dns" and registry "dns_recursive" are the same unit under different
# names, so they drift by construction. Worse, the legacy path shelled out
# with `sudo -S` -- which reads the password from stdin, where nothing
# supplied one, so the call could only ever fail.
#
# The registry (31 features, desired-vs-probed state, drift detection) is
# the single source of truth and these routes are a thin passthrough to
# it. No second store, no bypass of the intent queue, no `sudo -S`.
SIDECAR = "http://127.0.0.1:9192"


def _loopback(request: Request) -> None:
    """Control actions are loopback-only."""
    client = request.client.host if request and request.client else ""
    if client not in ("127.0.0.1", "::1"):
        raise HTTPException(403, "control actions are loopback-only")


async def _sidecar(method: str, path: str, body=None, timeout: int = 20):
    """Call the sidecar on loopback.

    ProxyHandler({}) is mandatory, not optional: this service has
    HTTP_PROXY=http://127.0.0.1:8118 injected, so urllib would otherwise
    route loopback calls to :9192 through privoxy and they would fail.
    """
    import urllib.request
    import urllib.error
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        SIDECAR + path, data=data, method=method,
        headers={"Content-Type": "application/json"})
    try:
        with opener.open(req, timeout=timeout) as r:
            return JSONResponse(json.loads(r.read().decode()),
                                status_code=r.status)
    except urllib.error.HTTPError as e:
        detail = e.read().decode()[:300]
        if e.code == 409:
            # An executor is already mid-flight for this feature. The
            # intent is queued and WILL be applied, so this is not a
            # failure -- reporting it as one makes a working toggle look
            # broken. Tell the caller to re-read the probed state.
            return JSONResponse({
                "ok": None,
                "queued": True,
                "message": ("an executor is already running for this "
                            "feature; the change is queued and will be "
                            "applied within a few seconds"),
                "detail": detail,
            }, status_code=202)
        return JSONResponse({"error": e.reason, "detail": detail},
                            status_code=e.code)
    except Exception as e:
        return JSONResponse({"error": f"{type(e).__name__}: {e}"[:300]},
                            status_code=502)


@app.get("/api/features")
async def api_features():
    """The authoritative feature registry, grouped by category."""
    return await _sidecar("GET", "/api/features/summary/categories")


@app.get("/api/features/{fid}")
async def api_feature_detail(fid: str):
    return await _sidecar("GET", f"/api/features/{fid}")


@app.post("/api/features/{fid}")
async def api_set_feature(fid: str, request: Request,
                          body: dict = Body(default_factory=dict)):
    """Switch one feature.

    `ok` in the response means the request was accepted AND the probe
    agrees -- not merely that the write succeeded. The UI must render the
    button from `effective`, never from the click.
    """
    _loopback(request)
    state = str(body.get("state", ""))
    if state not in ("on", "off"):
        return JSONResponse({"error": "state must be 'on' or 'off'"}, 400)
    return await _sidecar("POST", f"/api/features/{fid}", {"state": state},
                          timeout=90)


@app.get("/api/portmap")
async def api_portmap():
    """Authoritative port inventory, replacing a hardcoded list.

    The local table claimed tier-1 on :5399 was 'closed' while it was in
    fact listening -- it is a static guess, not a measurement.
    """
    return await _sidecar("GET", "/api/ports", timeout=45)


@app.get("/api/tech/status")
async def api_tech_status():
    """Technitium availability. It is normally NOT running; the UI must
    show that plainly rather than rendering an empty zone table."""
    return await _sidecar("GET", "/api/technitium/status")


@app.get("/api/logs")
async def api_logs(limit: int = 25):
    """Real tail of the resolver logs, not fabricated rows."""
    lines: list = []
    for path in ("/opt/souran-ai/logs/unbound.log",
                 "/opt/souran-ai/logs/unbound-dot.log"):
        try:
            with open(path, errors="replace") as fh:
                tail = fh.readlines()[-limit:]
            lines.append(f"--- {path} ---")
            lines.extend(t.rstrip() for t in tail)
        except OSError as exc:
            lines.append(f"--- {path}: {exc} ---")
    return PlainTextResponse("\n".join(lines) if lines else "no log files",
                             media_type="text/plain")


# ---------------------------------------------------------------------------
# Control surface — loopback only (this port is LAN-exposed)
# ---------------------------------------------------------------------------
@app.post("/api/control/{unit}/{action}")
async def api_control(unit: str, action: str, request: Request):
    client = request.client.host if request.client else ""
    if client not in ("127.0.0.1", "::1"):
        raise HTTPException(403, "control actions are loopback-only")
    if action not in ("restart", "start", "stop"):
        raise HTTPException(400, "unsupported action")
    if unit not in [s[0] for s in tel.SERVICES]:
        raise HTTPException(400, f"unknown unit {unit}")
    proc = subprocess.run(["sudo", "-n", "systemctl", action, unit],
                          capture_output=True, timeout=30)
    ok = proc.returncode == 0
    _record("Service control", f"{action} {unit}", ok)
    if not ok:
        raise HTTPException(500, (proc.stdout or proc.stderr)
                            .decode("utf-8", "replace")[:400])
    return JSONResponse({"ok": True, "unit": unit, "action": action})


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------
PAGE = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Souran &middot; Neuro Dashboard</title>
<style>
:root{
  --bg:#0b0f17; --panel:#131a26; --panel2:#182131; --line:#233047;
  --fg:#e8eef9; --mut:#8494ad; --acc:#5b8cff; --ok:#2fd48f;
  --warn:#ffb547; --bad:#ff5c72; --mono:ui-monospace,SFMono-Regular,Menlo,monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--fg);font:14px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
a{color:var(--acc)}
.wrap{max-width:1280px;margin:0 auto;padding:22px 20px 60px}
header{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:20px}
h1{font-size:19px;font-weight:650;letter-spacing:.2px}
.badge{font:600 11px/1 var(--mono);padding:6px 10px;border-radius:999px;
  background:var(--panel2);border:1px solid var(--line);color:var(--mut)}
.badge.ok{color:var(--ok);border-color:#1c5c44}
.badge.warn{color:var(--warn);border-color:#6b4c14}
.badge.bad{color:var(--bad);border-color:#6b2230}
.grid{display:grid;gap:14px}
.g4{grid-template-columns:repeat(auto-fit,minmax(210px,1fr))}
.g2{grid-template-columns:repeat(auto-fit,minmax(340px,1fr))}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}
.card h2{font-size:12px;font-weight:650;letter-spacing:.9px;text-transform:uppercase;
  color:var(--mut);margin-bottom:12px;display:flex;justify-content:space-between;align-items:center}
.k{font-size:30px;font-weight:660;font-variant-numeric:tabular-nums;letter-spacing:-.5px}
.k-sub{font-size:12px;color:var(--mut);margin-top:3px}
.hero{background:linear-gradient(140deg,#16203a,#131a26 60%);border:1px solid var(--line);
  border-radius:14px;padding:20px;margin-bottom:14px}
.hero .reason{color:var(--mut);margin-top:6px;font-size:13px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--mut);font-weight:600;font-size:11px;letter-spacing:.6px;
  text-transform:uppercase;padding:0 10px 8px 0;border-bottom:1px solid var(--line)}
td{padding:9px 10px 9px 0;border-bottom:1px solid #1b2436}
tr:last-child td{border-bottom:0}
.mono{font-family:var(--mono);font-size:12px}
.pill{font:600 11px/1 var(--mono);padding:4px 8px;border-radius:6px;white-space:nowrap}
.pill.ok{background:#10331f;color:var(--ok)}
.pill.bad{background:#33121a;color:var(--bad)}
.pill.warn{background:#33260f;color:var(--warn)}
.pill.off{background:#1c2434;color:var(--mut)}
.bar{height:6px;border-radius:4px;background:#1b2436;overflow:hidden;margin-top:6px}
.bar i{display:block;height:100%;background:var(--acc)}
.bar i.ok{background:var(--ok)}
.btn{background:var(--panel2);color:var(--fg);border:1px solid var(--line);
  padding:7px 12px;border-radius:8px;cursor:pointer;font-size:12px;font-weight:600}
.btn:hover{border-color:var(--acc);color:var(--acc)}
.btn:disabled{opacity:.5;cursor:not-allowed}
.empty{color:var(--mut);font-style:italic;padding:10px 0}
.note{color:var(--mut);font-size:12px;margin-top:10px}
footer{margin-top:26px;color:var(--mut);font-size:12px;text-align:center}
code{font-family:var(--mono);background:var(--panel2);padding:1px 6px;border-radius:5px;font-size:12px}
</style></head><body><div class="wrap">
<header>
  <h1>Souran &middot; Neuro Dashboard</h1>
  <span id="verdict" class="badge">loading&hellip;</span>
  <span style="flex:1"></span>
  <span class="badge" id="stamp">&mdash;</span>
  <button class="btn" id="probeBtn">Run resolution probe</button>
  <button class="btn" onclick="load()">Refresh</button>
</header>

<div class="hero">
  <div class="k" id="heroVal">&hellip;</div>
  <div class="reason" id="heroReason">Reading live resolver state&hellip;</div>
</div>

<div class="grid g4" id="stats"></div>

<div class="grid g2" style="margin-top:14px">
  <div class="card"><h2>Resolution paths</h2><div id="paths"></div></div>
  <div class="card"><h2>Censorship posture</h2><div id="egress"></div></div>
  <div class="card"><h2>Services</h2><div id="services"></div></div>
  <div class="card"><h2>Listeners</h2><div id="ports"></div></div>
  <div class="card"><h2>Bypass stack</h2><div id="bypass"></div></div>
  <div class="card"><h2>Activity <span id="evCount" class="mono" style="color:var(--mut)"></span></h2>
    <div id="events" style="max-height:290px;overflow:auto"></div></div>
  <div class="card"><h2>Feature Toggles <button class="btn" id="toggleAllOn" style="float:right;margin-left:6px">ALL ON</button> <button class="btn" id="toggleAllOff" style="float:right">ALL OFF</button></h2><div id="toggles" style="max-height:400px;overflow:auto"></div></div>
</div>

<footer>Every figure is read live from this host &mdash; nothing hardcoded &middot;
snapshot in <span id="collect">?</span> ms</footer>
</div>
<script>
const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[<>&]/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]));
const num = n => (n ?? 0).toLocaleString();
function bar(pct, cls){ pct = Math.max(0, Math.min(100, pct || 0));
  return '<div class="bar"><i class="' + (cls||'') + '" style="width:' + pct + '%"></i></div>'; }

async function load(){
  let d;
  try { d = await (await fetch('/api/status')).json(); }
  catch(e){ $('#verdict').textContent = 'dashboard cannot reach API'; return; }

  const v = d.resolver_health || {};
  const cls = v.level === 'healthy' ? 'ok' : v.level === 'critical' ? 'bad' : 'warn';
  $('#verdict').className = 'badge ' + cls;
  $('#verdict').textContent = v.level ? v.level.toUpperCase() : 'UNKNOWN';
  $('#stamp').textContent = d.generated_at || '';

  $('#heroVal').textContent = num(v.total) + ' queries';
  $('#heroVal').style.color = cls === 'ok' ? 'var(--ok)' : 'var(--bad)';
  $('#heroReason').textContent = v.reason || 'no verdict';

  const s = d.resolver_totals || {};
  const u = d.unbound || {};
  const total = (s.primary||0)+(s.fallback||0)+(s.fail||0);
  const t1 = total ? 100*(s.primary||0)/total : 0;
  const hr = (u.available && (u.cache_hits + u.cache_miss))
    ? 100*u.cache_hits/(u.cache_hits+u.cache_miss) : null;

  $('#stats').innerHTML =
    '<div class="card"><h2>Poison blocked</h2>' +
      '<div class="k" style="color:var(--ok)">' + num(s.poisoned) + '</div>' +
      '<div class="k-sub">injected answers refused</div></div>' +
    '<div class="card"><h2>Tier 1 &middot; zero-upstream</h2>' +
      '<div class="k">' + num(s.primary) + '</div>' +
      '<div class="k-sub">answered by local unbound</div>' + bar(t1) + '</div>' +
    '<div class="card"><h2>Tier 2 &middot; DoH</h2>' +
      '<div class="k">' + num(s.fallback) + '</div>' +
      '<div class="k-sub">encrypted fallback</div></div>' +
    '<div class="card"><h2>Failed</h2>' +
      '<div class="k" style="color:' + ((s.fail||0) > 0 ? 'var(--warn)' : 'var(--ok)') + '">' +
      num(s.fail) + '</div><div class="k-sub">unresolved by any tier</div></div>' +
    '<div class="card"><h2>Unbound cache hit</h2>' +
      '<div class="k">' + (hr === null ? '&mdash;' : hr + '%') + '</div>' +
      '<div class="k-sub">' + (u.available ? num(u.queries) + ' queries' : 'unavailable') + '</div>' +
      (hr === null ? '' : bar(hr,'ok')) + '</div>' +
    '<div class="card"><h2>Cache entries</h2>' +
      '<div class="k">' + num(d.resolver && d.resolver.cache_entries) + '</div>' +
      '<div class="k-sub">held by front-end</div></div>';

  $('#paths').innerHTML = '<table><tr><th>Path</th><th>Status</th></tr>' +
    '<tr><td>Tier 1 &mdash; unbound iterative <code>:5399</code></td><td>' +
      '<span class="pill ' + (u.available?'ok':'bad') + '">' + (u.available?'live':'down') + '</span></td></tr>' +
    '<tr><td>Tier 2 &mdash; DoH via proxy <code>:8118</code></td><td>' +
      '<span class="pill ' + (d.bypass.proxy_8118?'ok':'bad') + '">' + (d.bypass.proxy_8118?'up':'down') + '</span></td></tr>' +
    '<tr><td>Tor SOCKS <code>:9050</code></td><td>' +
      '<span class="pill ' + (d.bypass.tor_socks_9050?'ok':'bad') + '">' + (d.bypass.tor_socks_9050?'up':'down') + '</span></td></tr>' +
    '<tr><td>Primary upstream</td><td class="mono">' + esc(d.resolver.primary_upstream || '-') + '</td></tr>' +
    '<tr><td>DoH fallback</td><td class="mono" style="word-break:break-all">' + esc(d.resolver.doh_fallback || '-') + '</td></tr>' +
    '</table>';

  const e = d.egress || {};
  $('#egress').innerHTML = e.available ?
    '<table>' +
    '<tr><td>Resolver NAT exemption</td><td><span class="pill ' + (e.resolver_bypass_ok?'ok':'bad') + '">' +
      (e.resolver_bypass_ok?'present':'MISSING') + '</span></td></tr>' +
    '<tr><td>Tor DNS intercept</td><td>' + (e.tor_dns_redirect||[]).length + ' rule(s)</td></tr>' +
    '<tr><td>Tunnel redirect</td><td>' + (e.cloudflare_redirect||[]).length + ' rule(s)</td></tr>' +
    '<tr><td>Total NAT rules</td><td>' + num(e.total_rules) + '</td></tr></table>' +
    '<p class="note">A missing exemption means root priming is hijacked to Tor and DNS dies &mdash; ' +
    'this is the check that would have caught the 22-hour outage.</p>'
    : '<div class="empty">iptables unavailable (needs sudo)</div>';

  $('#services').innerHTML = '<table><tr><th>Unit</th><th>State</th></tr>' +
    (d.services||[]).map(function(s){
      return '<tr><td>' + esc(s.unit) + '<div style="color:var(--mut);font-size:12px">' +
        esc(s.description) + (s.critical ? ' &middot; critical' : '') + '</div></td>' +
        '<td><span class="pill ' + (s.active?'ok':'bad') + '">' + esc(s.state) + '</span></td></tr>';
    }).join('') + '</table>';

  $('#ports').innerHTML = '<table><tr><th>Port</th><th>Proto</th><th>State</th></tr>' +
    (d.listeners||[]).map(function(p){
      return '<tr><td class="mono">' + p.port + '</td><td>' + esc(p.proto) + '</td>' +
        '<td><span class="pill ' + (p.listening?'ok':'bad') + '">' +
        (p.listening?'listening':'closed') + '</span></td></tr>';
    }).join('') + '</table>';

  const b = d.bypass || {}, m = b.modes || {};
  $('#bypass').innerHTML = '<table>' +
    '<tr><td>Tor</td><td><span class="pill ' + (m.tor==='active'?'ok':'off') + '">' + esc(m.tor||'n/a') + '</span></td></tr>' +
    '<tr><td>Ouinet</td><td><span class="pill ' + (m.ouinet?'ok':'off') + '">' + esc(m.ouinet||'not installed') + '</span></td></tr>' +
    '<tr><td>Snowflake</td><td><span class="pill ' + (m.snowflake?'ok':'off') + '">' + esc(m.snowflake||'not installed') + '</span></td></tr>' +
    '</table><p class="note">' + esc(b.doh_note || '') + '</p>';

  $('#collect').textContent = d.collect_ms ?? '?';
  loadEvents();
}

async function loadEvents(){
  try{
    const e = await (await fetch('/api/events?limit=25')).json();
    const ev = e.events || [];
    $('#evCount').textContent = ev.length ? '(' + ev.length + ')' : '';
    $('#events').innerHTML = ev.length ? ev.map(function(x){
      return '<div style="padding:7px 0;border-bottom:1px solid #1b2436">' +
        '<div style="display:flex;gap:8px;align-items:center">' +
        '<span class="pill ' + (x.ok?'ok':'bad') + '">' + esc(x.event) + '</span>' +
        '<span class="mono" style="color:var(--mut);font-size:11px">' + esc(x.time.slice(11,19)) + '</span></div>' +
        '<div style="font-size:12px;margin-top:3px">' + esc(x.details) + '</div></div>';
    }).join('') : '<div class="empty">No activity yet &mdash; run a resolution probe.</div>';
  }catch(e){}
}

$('#probeBtn').addEventListener('click', async function(){
  const btn = this; btn.disabled = true; btn.textContent = 'Testing...';
  try{
    const r = await (await fetch('/api/probe?count=6')).json();
    const lines = r.results.map(function(x){
      return (x.ok ? 'OK  ' : 'FAIL') + ' ' + x.domain + '  ' + x.ms + 'ms  ' +
             (x.answers.join(', ') || x.status);
    }).join('\\n');
    alert(r.passed + '/' + r.total + ' resolved\\nPoison-free: ' + (r.poison_free?'YES':'NO') + '\\n\\n' + lines);
    load();
  } catch(e){ alert('probe failed: ' + e); }
  finally { btn.disabled = false; btn.textContent = 'Run resolution probe'; }
});

// --- Feature toggles ---
async function loadToggles(){
  try{
    const d = await (await fetch('/api/toggles')).json();
    const names = Object.keys(d);
    $('#toggles').innerHTML = names.map(function(n){
      const f = d[n];
      const on = f.configured;
      return '<div style=\"display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid #1b2436\">' +
        '<span style=\"flex:1;min-width:120px\">' + esc(f.label || n) + '</span>' +
        '<span style=\"color:var(--mut);font-size:11px;min-width:60px\">:' + (f.port||'—') + '</span>' +
        '<span class=\"pill ' + (f.live?'ok':'bad') + '\" style=\"min-width:50px;text-align:center\">' + (f.live?'live':'down') + '</span>' +
        '<button class=\"btn ' + (on?'ok':'bad') + '\" onclick=\"toggleFeature(\\'' + n + '\\', ' + (!on) + ')\" style=\"min-width:60px\">' + (on?'ON':'OFF') + '</button>' +
        '</div>';
    }).join('');
  }catch(e){ $('#toggles').innerHTML = '<div class=\"empty\">toggle unavailable</div>'; }
}
async function toggleFeature(name, enabled){
  try{
    const url = '/api/toggle/' + name + '?enabled=' + enabled;
    await fetch(url, {method:'POST'});
    loadToggles();
    load();
  }catch(e){ alert('toggle failed: ' + e); }
}
$('#toggleAllOn').addEventListener('click', async function(){
  try{ await fetch('/api/toggles?enabled=true', {method:'POST'}); }catch(e){}
  loadToggles(); load();
});
$('#toggleAllOff').addEventListener('click', async function(){
  try{ await fetch('/api/toggles?enabled=false', {method:'POST'}); }catch(e){}
  loadToggles(); load();
});

load();
setInterval(load, 15000);
</script></body></html>"""


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(PAGE)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8383, log_level="warning")