#!/usr/bin/env python3
"""
Souran AI Network Server v5.1.0 — Control Dashboard
File: souran_dashboard.py   |  Port: 8082 (Hermes control surface)

WHAT THIS REPLACES
------------------
The dashboard on :8082 was a static page that hardcoded its values and
offered no controls at all: 26 individually-switchable features, the port
inventory and the DNS/Technitium surface all existed with no way to reach
them from a browser. This is the UI for the registry.

DESIGN NOTES
------------
- Read-only data comes from the sidecar on loopback :9192, which is the
  single source of truth for the feature registry, the port map and the
  Technitium client. The dashboard never invents state.
- Mutations POST to the sidecar, which queues an intent for the privileged
  executor. Because that is asynchronous (a 15 s timer), the UI shows the
  ACTUAL probed state, not the requested state, and says so plainly when
  they differ. A toggle that appears to work but did nothing is worse than
  no toggle.
- No token is required from loopback; from anywhere else the sidecar
  enforces souran_auth. This process binds 127.0.0.1 only when
  SOURAN_DASHBOARD_BIND says so, and defaults to all interfaces because
  the operator reaches it from the cafe LAN — the firewall already limits
  that to the LAN service set.
"""

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SIDECAR = os.environ.get("SOURAN_SIDECAR_URL", "http://127.0.0.1:9192")
PORT = int(os.environ.get("SOURAN_DASHBOARD_PORT", "8082"))
VERSION = "5.1.0"


def sidecar(path, method="GET", payload=None, timeout=30):
    """Call the sidecar. Returns (ok, data)."""
    url = SIDECAR.rstrip("/") + path
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers,
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return True, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return False, json.loads(e.read().decode())
        except Exception:
            return False, {"error": f"HTTP {e.code}"}
    except Exception as e:
        return False, {"error": f"{type(e).__name__}: {e}"}


def gather():
    """Collect everything the dashboard renders, in one place."""
    out = {"version": VERSION,
           "generated_at": datetime.now(timezone.utc).isoformat(),
           "errors": []}

    ok, features = sidecar("/api/features/summary/categories", timeout=45)
    if ok:
        out["features"] = features
    else:
        out["errors"].append(f"feature registry: {features.get('error')}")
        out["features"] = {"summary": {}, "categories": {}}

    ok, ports = sidecar("/api/ports", timeout=45)
    if ok:
        out["ports"] = ports
    else:
        out["errors"].append(f"port map: {ports.get('error')}")

    ok, health = sidecar("/api/health", timeout=10)
    out["health"] = health if ok else {"status": "unreachable"}

    ok, tech = sidecar("/api/technitium/status", timeout=20)
    out["technitium"] = tech if ok else {"available": False,
                                         "error": tech.get("error")}

    ok, auth = sidecar("/api/auth/state", timeout=10)
    out["auth"] = auth if ok else {}

    return out


# --------------------------------------------------------------------------
# UI
# --------------------------------------------------------------------------
PAGE = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Souran AI Network Server — Control</title>
<style>
  :root{
    --bg:#07090f; --panel:#0e1220; --panel2:#141a2c; --line:#1e2740;
    --fg:#dfe6f5; --dim:#8592ad; --accent:#00d4ff; --ok:#00e58a;
    --warn:#ffb020; --bad:#ff5470; --drift:#c77dff;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--fg);
       font:15px/1.5 ui-sans-serif,system-ui,"Segoe UI",Roboto,sans-serif;
       padding-bottom:60px}
  header{position:sticky;top:0;z-index:20;background:linear-gradient(180deg,#0a0e1a,#07090f);
         border-bottom:1px solid var(--line);padding:18px 26px}
  .row{display:flex;gap:16px;align-items:center;flex-wrap:wrap}
  h1{font-size:21px;color:var(--accent);letter-spacing:.4px}
  .sub{color:var(--dim);font-size:13px}
  .grow{flex:1}
  .pill{background:var(--panel2);border:1px solid var(--line);border-radius:20px;
        padding:5px 13px;font-size:12.5px;color:var(--dim)}
  .pill b{color:var(--fg)}
  main{max-width:1500px;margin:0 auto;padding:22px 26px}
  section{margin-bottom:30px}
  h2{font-size:15px;text-transform:uppercase;letter-spacing:1.4px;
     color:var(--dim);margin-bottom:12px;display:flex;align-items:center;gap:10px}
  h2::after{content:"";flex:1;height:1px;background:var(--line)}
  .cards{display:grid;gap:12px;grid-template-columns:repeat(auto-fill,minmax(330px,1fr))}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:12px;
        padding:15px 16px;transition:border-color .18s}
  .card:hover{border-color:#2b3a5c}
  .card.drift{border-color:var(--drift)}
  .ch{display:flex;align-items:flex-start;gap:11px;margin-bottom:9px}
  .cname{font-weight:600;font-size:14.5px;flex:1}
  .cdesc{color:var(--dim);font-size:12.5px;margin-bottom:11px;min-height:32px}
  .meta{font-size:11.5px;color:#5f6b85;margin-top:9px;word-break:break-all}
  /* switch */
  .sw{position:relative;width:46px;height:25px;flex:0 0 46px;cursor:pointer}
  .sw input{opacity:0;width:0;height:0}
  .sl{position:absolute;inset:0;background:#2a3350;border-radius:25px;transition:.22s}
  .sl::before{content:"";position:absolute;height:19px;width:19px;left:3px;top:3px;
              background:#8592ad;border-radius:50%;transition:.22s}
  .sw input:checked + .sl{background:rgba(0,229,138,.28)}
  .sw input:checked + .sl::before{transform:translateX(21px);background:var(--ok)}
  .sw input:disabled + .sl{opacity:.4;cursor:not-allowed}
  .tag{font-size:10.5px;padding:2px 7px;border-radius:5px;letter-spacing:.5px;
       text-transform:uppercase;font-weight:700}
  .t-on{background:rgba(0,229,138,.16);color:var(--ok)}
  .t-off{background:rgba(255,84,112,.16);color:var(--bad)}
  .t-drift{background:rgba(199,125,255,.16);color:var(--drift)}
  .t-dep{background:rgba(255,176,32,.16);color:var(--warn)}
  table{width:100%;border-collapse:collapse;font-size:12.5px}
  th{text-align:left;color:var(--dim);font-weight:600;padding:7px 9px;
     border-bottom:1px solid var(--line);font-size:11px;text-transform:uppercase;
     letter-spacing:.7px}
  td{padding:6px 9px;border-bottom:1px solid #131a2b}
  tr:hover td{background:rgba(255,255,255,.022)}
  .mono{font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace}
  .warnbox{background:rgba(255,176,32,.09);border:1px solid var(--warn);
           border-radius:10px;padding:11px 14px;color:var(--warn);font-size:13px;
           margin-bottom:16px}
  .stat{background:var(--panel);border:1px solid var(--line);border-radius:10px;
        padding:13px 15px}
  .stat .n{font-size:26px;font-weight:700;color:var(--accent);line-height:1.1}
  .stat .l{color:var(--dim);font-size:11.5px;text-transform:uppercase;
           letter-spacing:.8px;margin-top:3px}
  .stats{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
         margin-bottom:22px}
  .scroll{max-height:430px;overflow:auto;border:1px solid var(--line);
          border-radius:10px}
  .empty{color:var(--dim);padding:22px;text-align:center;font-size:13px}
  .toast{position:fixed;bottom:18px;left:50%;transform:translateX(-50%);
         background:var(--panel2);border:1px solid var(--accent);color:var(--fg);
         padding:11px 20px;border-radius:9px;font-size:13px;z-index:60;
         box-shadow:0 8px 30px rgba(0,0,0,.55);display:none;max-width:80vw}
  .toast.err{border-color:var(--bad)}
  .toast.ok{border-color:var(--ok)}
  footer{text-align:center;color:var(--dim);font-size:12px;padding:26px 20px}
  a{color:var(--accent)}
</style></head><body>
<header>
  <div class="row">
    <div>
      <h1>&#9679; Souran AI Network Server</h1>
      <div class="sub" id="hdr-sub">control surface &middot; loading&hellip;</div>
    </div>
    <div class="grow"></div>
    <span class="pill">version <b id="v">—</b></span>
    <span class="pill">sidecar <b id="sc">—</b></span>
    <span class="pill" id="refreshed">—</span>
  </div>
</header>

<main>
  <div id="errors"></div>

  <div class="stats" id="stats"></div>

  <section>
    <h2>Features &mdash; every capability, individually switchable</h2>
    <div id="features"></div>
  </section>

  <section>
    <h2>Port map &mdash; every listening socket on this host</h2>
    <div class="scroll"><table id="ports">
      <thead><tr><th>Port</th><th>Proto</th><th>Scope</th><th>Process</th>
        <th>Service</th><th>Purpose</th><th>Verdict</th></tr></thead>
      <tbody></tbody></table></div>
  </section>

  <section>
    <h2>DNS resolver &amp; server</h2>
    <div class="cards" id="dns"></div>
  </section>
</main>

<footer>
  Souran AI Network Server v5.1.0 &middot; zero-upstream recursive resolver
  &middot; every feature independently switchable &middot;
  <a href="http://127.0.0.1:8383/">web dashboard</a>
</footer>

<div class="toast" id="toast"></div>

<script>
const $ = s => document.querySelector(s);
const esc = s => String(s==null?'':s).replace(/[&<>"']/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function toast(msg, kind){
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast ' + (kind||'');
  t.style.display = 'block';
  clearTimeout(t._h);
  t._h = setTimeout(()=>t.style.display='none', 5200);
}

async function api(path, method, body){
  const opt = {method: method||'GET', headers:{}};
  if(body){ opt.headers['Content-Type']='application/json';
           opt.body = JSON.stringify(body); }
  const r = await fetch(path, opt);
  let d = null;
  try { d = await r.json(); } catch(e) {}
  return {ok: r.ok, status: r.status, data: d};
}

async function toggle(id, want, label){
  const r = await api('/api/feature', 'POST', {id, state: want});
  if(!r.ok){
    toast(`${label}: ${(r.data&&r.data.error)||('HTTP '+r.status)}`, 'err');
    return;
  }
  const res = r.data.result || {};
  if(res.ok){
    toast(`${label} -> ${res.effective.toUpperCase()} (verified)`, 'ok');
  } else {
    toast(`${label}: ${res.note || 'applied but NOT verified'}`, 'err');
  }
  load();
}

function featureCard(f){
  const on = f.effective === 'on';
  const drift = f.drift;
  const unmet = (f.unmet_requirements||[]);
  let tag = '';
  if(unmet.length) tag = `<span class="tag t-dep">needs ${esc(unmet.join(', '))}</span>`;
  else if(drift) tag = `<span class="tag t-drift">drift</span>`;
  else tag = `<span class="tag ${on?'t-on':'t-off'}">${on?'on':'off'}</span>`;
  return `<div class="card ${drift?'drift':''}">
    <div class="ch">
      <div class="cname">${esc(f.label)}</div>
      ${tag}
      <label class="sw" title="${on?'Disable':'Enable'}">
        <input type="checkbox" ${on?'checked':''} ${unmet.length?'disabled':''}
          onchange="toggle('${esc(f.id)}', this.checked?'on':'off', '${esc(f.label).replace(/'/g,"")}')">
        <span class="sl"></span>
      </label>
    </div>
    <div class="cdesc">${esc(f.description||'')}</div>
    <div class="meta">${esc(f.detail||'')} &middot; desired:
      <b>${esc(f.desired)}</b> &middot; actual: <b>${esc(f.effective)}</b></div>
  </div>`;
}

function dnsCard(title, body){
  return `<div class="card"><div class="ch"><div class="cname">${esc(title)}</div></div>
          <div class="cdesc">${body}</div></div>`;
}

async function load(){
  let d;
  try { d = await (await fetch('/api/dashboard')).json(); }
  catch(e){ toast('dashboard fetch failed: '+e, 'err'); return; }

  $('#v').textContent = d.version;
  $('#sc').textContent = (d.health&&d.health.status)||'unreachable';
  $('#hdr-sub').textContent =
    `control surface · ${d.summary.on}/${d.summary.total} features active` +
    (d.summary.drifted ? ` · ${d.summary.drifted} drifted` : ' · no drift');
  $('#refreshed').textContent = 'updated ' +
    new Date(d.generated_at).toLocaleTimeString();

  $('#errors').innerHTML = (d.errors||[]).length
    ? `<div class="warnbox"><b>Partial data:</b> ${d.errors.map(esc).join(' &middot; ')}</div>`
    : '';

  $('#stats').innerHTML = `
    <div class="stat"><div class="n">${d.summary.on}/${d.summary.total}</div>
      <div class="l">features active</div></div>
    <div class="stat"><div class="n">${d.summary.drifted}</div>
      <div class="l">drifted</div></div>
    <div class="stat"><div class="n">${d.ports_summary.distinct_ports}</div>
      <div class="l">ports mapped</div></div>
    <div class="stat"><div class="n">${d.ports_summary.souran_ports}</div>
      <div class="l">souran-owned</div></div>
    <div class="stat"><div class="n">${d.ports_summary.all_interfaces}</div>
      <div class="l">on all ifaces</div></div>
    <div class="stat"><div class="n">${d.ports_summary.unidentified_ports.length}</div>
      <div class="l">unidentified</div></div>`;

  const cats = d.categories || {};
  $('#features').innerHTML = Object.keys(cats).length
    ? Object.entries(cats).map(([c, list]) =>
        `<h3 style="font-size:13px;color:var(--dim);margin:16px 0 9px;
          text-transform:uppercase;letter-spacing:1px">${esc(c)}</h3>
         <div class="cards">${list.map(featureCard).join('')}</div>`).join('')
    : `<div class="empty">feature registry unavailable</div>`;

  const rows = (d.ports||[]).map(p => `<tr>
      <td class="mono">${p.port}</td><td class="mono">${esc(p.proto)}</td>
      <td>${esc(p.scope)}</td><td class="mono">${esc(p.process||'-')}</td>
      <td>${esc(p.name)}</td>
      <td style="color:var(--dim)">${esc((p.purpose||'').slice(0,90))}</td>
      <td>${p.verdict==='ok' ? '<span class="tag t-on">ok</span>'
             : `<span class="tag t-off">${esc(p.verdict)}</span>`}</td>
    </tr>`).join('');
  $('#ports tbody').innerHTML = rows ||
    `<tr><td colspan="7" class="empty">no data</td></tr>`;

  const t = d.technitium || {};
  $('#dns').innerHTML =
    dnsCard('Zero-upstream recursive resolver',
      `unbound resolves from the root hints with no forwarders. ` +
      `Cache, prefetch and serve-expired are on. ` +
      `Upstream queries use <b>TCP</b> because plain UDP/53 is forged on ` +
      `this network.`) +
    dnsCard('Poison-proof front-end (:53)',
      `Answers are cross-checked: an RFC1918/loopback answer for a public ` +
      `name is this censor's injection signature and is rejected, then ` +
      `escalated to DoH over HTTPS/443.`) +
    dnsCard('DNSSEC validation',
      d.features_summary_dnssec ||
      `Currently <b>permissive</b>. Tor strips RRSIG records, so strict ` +
      `validation cannot succeed over the Tor transport; it is a ` +
      `per-feature toggle for a direct, un-tunnelled path.`) +
    dnsCard('Technitium DNS Server',
      t.available
        ? `Running at <span class="mono">${esc(t.base)}</span>. Zone and ` +
          `record management is available under /api/technitium/.`
        : `<span style="color:var(--warn)">Not running</span> — ` +
          `${esc(t.error||'no response')}. The Souran resolver above is ` +
          `the active DNS path.`) +
    dnsCard('Control-plane security',
      (d.auth && d.auth.ok)
        ? `API token present at <span class="mono">${esc(d.auth.path)}</span>, ` +
          `${esc(d.auth.mode)}, ${d.auth.length} chars.`
        : `Token state: ${esc((d.auth&&d.auth.problems||['unknown']).join('; '))}`);
}

load();
setInterval(load, 20000);
</script>
</body></html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = f"Souran/{VERSION}"

    def log_message(self, format, *a):
        pass  # keep the journal clean

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, indent=2).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            return self._send(200, PAGE, "text/html; charset=utf-8")
        if path == "/health":
            return self._send(200, {"status": "ok", "version": VERSION})
        if path == "/api/dashboard":
            d = gather()
            # Read the port report's summary BEFORE replacing the report
            # with its entry list -- assigning d["ports"] first destroyed
            # the dict and the next line raised AttributeError, which
            # surfaced to the browser as an empty 502.
            ports_report = d.get("ports") or {}
            d["ports_summary"] = ports_report.get("summary", {
                "distinct_ports": 0, "souran_ports": 0,
                "all_interfaces": 0, "unidentified_ports": []})
            d["ports"] = ports_report.get("entries", [])
            d["summary"] = (d.get("features") or {}).get("summary", {})
            d["categories"] = (d.get("features") or {}).get("categories", {})
            return self._send(200, d)
        if path == "/api/ports":
            ok, data = sidecar("/api/ports", timeout=45)
            return self._send(200 if ok else 502, data)
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path.split("?")[0] != "/api/feature":
            return self._send(404, {"error": "not found"})
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception as e:
            return self._send(400, {"error": f"bad body: {e}"})

        fid = str(body.get("id", ""))
        state = str(body.get("state", ""))
        if not fid or state not in ("on", "off"):
            return self._send(400, {"error": "id and state(on|off) required"})

        ok, data = sidecar(f"/api/features/{fid}", "POST", {"state": state},
                           timeout=90)
        return self._send(200 if ok else 502,
                          {"result": data} if ok else {"error": data})


def main():
    bind = os.environ.get("SOURAN_DASHBOARD_BIND", "0.0.0.0")
    srv = ThreadingHTTPServer((bind, PORT), Handler)
    print(f"[souran-dashboard] v{VERSION} listening on {bind}:{PORT}",
          flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
