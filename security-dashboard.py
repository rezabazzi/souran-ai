#!/usr/bin/env python3
# Version: v5.1.0 | Souran AI Network Server

"""
Souran AI Network Server v4.3.1 — Security Monitoring Dashboard
Port 8083 — Real-time security overview: blocked IPs, failed logins, active connections, threat levels
"""
import http.server, json, subprocess, time, re, os, threading
from urllib.parse import urlparse
from datetime import datetime, timedelta

VERSION = "4.3.1"
PORT = 8083
LOG_DIR = "/var/log"
WATCHDOG_LOG = "/var/log/souran-watchdog/watchdog.log"
AI_LOG = "/var/log/souran-ai.log"
AUTH_LOG = "/var/log/auth.log"
AI_WATCHDOG_LOG = "/var/log/souran-ai-watchdog.log"

def get_threat_level(blocked_ips, failed_logins, suspicious_ips):
    score = 0
    if blocked_ips: score += min(len(blocked_ips), 20) * 0.5
    if failed_logins: score += min(len(failed_logins), 30) * 1.0
    if suspicious_ips: score += len(suspicious_ips) * 2.0
    if score > 50: return "CRITICAL", score
    if score > 25: return "HIGH", score
    if score > 10: return "MEDIUM", score
    return "LOW", score

def collect_blocked_ips():
    blocked = []
    try:
        r = subprocess.run(['iptables','-L','INPUT','-n','--line-numbers'], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            if 'DROP' in line or 'REJECT' in line:
                parts = line.split()
                if len(parts) >= 4 and parts[3] != '0.0.0.0/0':
                    ip = parts[3].split('/')[0] if '/' in parts[3] else parts[3]
                    if ip and ip != '0.0.0.0':
                        blocked.append({"ip": ip, "action": line.split()[-1], "rule_num": parts[0] if parts[0].isdigit() else "?"})
    except Exception: pass
    try:
        r = subprocess.run(['grep','-h','DROP\|REJECT\|BLOCK\|blocked',WATCHDOG_LOG], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines()[-20:]:
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            for ip in ips:
                if ip not in [b['ip'] for b in blocked]:
                    blocked.append({"ip": ip, "action": "watchdog", "rule_num": "-"})
    except Exception: pass
    return blocked

def collect_failed_logins():
    failed = []
    try:
        r = subprocess.run(['grep','-h','Failed password\|Invalid user\|authentication failure\|authentication error',AUTH_LOG], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            m = re.match(r'(\d{4}-\d{2}-\d{2}T[\d:.+-]+)', line)
            ts = m.group(1) if m else datetime.utcnow().isoformat()
            ip_match = re.findall(r'from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            user_match = re.findall(r'for (invalid user )?(\w+)', line)
            failed.append({"timestamp": ts, "ip": ip_match[0] if ip_match else "unknown", "user": user_match[0][1] if user_match else (user_match[0][0] if user_match else "unknown"), "line": line.strip()[:120]})
    except Exception: pass
    return failed[-50:]

def collect_active_connections():
    conns = []
    try:
        r = subprocess.run(['ss','-tlnp'], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4:
                proc = ""
                for p in parts[4:]:
                    if 'users:' in p:
                        proc = p.split('"')[1] if '"' in p else p
                        break
                conns.append({"state": parts[0], "local": parts[3], "process": proc or "unknown"})
    except Exception: pass
    return conns

def collect_suspicious_ips():
    suspicious = set()
    try:
        r = subprocess.run(['grep','-h','ERROR\|ALERT\|WARNING\|FAILED\|unhealthy',AI_WATCHDOG_LOG], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            for ip in ips: suspicious.add(ip)
    except Exception: pass
    try:
        r = subprocess.run(['grep','-h','FAILED\|ERROR\|ALERT\|block\|BLOCK\|suspicious',WATCHDOG_LOG], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines()[-30:]:
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            for ip in ips:
                if ip not in ['127.0.0.1']: suspicious.add(ip)
    except Exception: pass
    return list(suspicious)[:20]

def collect_security_events():
    events = []
    patterns = [(r'\[ERROR\]','error'),(r'\[ALERT\]','alert'),(r'\[WARN.*\]','warning'),(r'ERROR:','error'),(r'ALERT:','alert'),(r'FAILED','error'),(r'RESTART','info'),(r'BLOCK','block'),(r'sidecar.*FAILED','error')]
    for logfile in [AI_LOG, AI_WATCHDOG_LOG, WATCHDOG_LOG]:
        try:
            r = subprocess.run(['tail','-50',logfile], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                level = 'info'
                for pat, lvl in patterns:
                    if re.search(pat, line): level = lvl; break
                if level in ('error','alert','warning'):
                    events.append({"timestamp": datetime.utcnow().isoformat(), "level": level, "source": logfile, "message": line.strip()[:150]})
        except Exception: pass
    return events[-30:]

def collect_disk_and_system():
    sys_info = {}
    try:
        r = subprocess.run(['df','-h','/'], capture_output=True, text=True, timeout=5)
        lines = r.stdout.strip().splitlines()
        if len(lines) >= 2:
            parts = lines[1].split()
            sys_info['disk_used'] = parts[4] if len(parts) > 4 else '?'
            sys_info['disk_total'] = parts[1] if len(parts) > 1 else '?'
    except Exception: pass
    try:
        r = subprocess.run(['free','-h'], capture_output=True, text=True, timeout=5)
        lines = r.stdout.strip().splitlines()
        if len(lines) >= 2:
            parts = lines[1].split()
            sys_info['mem_used'] = parts[2] if len(parts) > 2 else '?'
            sys_info['mem_total'] = parts[1] if len(parts) > 1 else '?'
    except Exception: pass
    try:
        r = subprocess.run(['uptime','-p'], capture_output=True, text=True, timeout=5)
        sys_info['uptime'] = r.stdout.strip()
    except Exception: pass
    return sys_info

def build_html(data):
    threat, threat_score = get_threat_level(data['blocked_ips'], data['failed_logins'], data['suspicious_ips'])
    threat_colors = {"LOW":"#0f0","MEDIUM":"#ff0","HIGH":"#f80","CRITICAL":"#f00"}
    threat_color = threat_colors.get(threat, "#0f0")
    tc = data['total_connections'] if 'total_connections' in data else len(data['active_connections'])
    blocked_rows = ''.join(f"<tr><td>{b['ip']}</td><td>{b['action']}</td><td>{b['rule_num']}</td></tr>" for b in data['blocked_ips'][:20]) or "<tr><td colspan='3'>No blocked IPs found</td></tr>"
    failed_rows = ''.join(f"<tr><td>{f['timestamp'][:19]}</td><td>{f['ip']}</td><td>{f['user']}</td><td>{f['line'][:80]}</td></tr>" for f in data['failed_logins'][:20]) or "<tr><td colspan='4'>No failed logins detected</td></tr>"
    conn_rows = ''.join(f"<tr><td><span class='dot {c['state'].lower()}'></span></td><td>{c['state']}</td><td>{c['local']}</td><td>{c['process'][:30]}</td></tr>" for c in data['active_connections'][:15]) or "<tr><td colspan='4'>No active connections</td></tr>"
    sus_rows = ''.join(f"<tr><td>{ip}</td><td>✓</td></tr>" for ip in data['suspicious_ips']) or "<tr><td colspan='2'>No suspicious IPs detected</td></tr>"
    event_rows = ''.join(f"<tr><td><span class='dot {e['level']}'></span></td><td>{e['timestamp'][:19]}</td><td><code>{e['message'][:100]}</code></td></tr>" for e in data['security_events'][:20]) or "<tr><td colspan='3'>No security events</td></tr>"
    html = f"""<!DOCTYPE html><html><head><title>Souran AI Security Dashboard v{VERSION}</title>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{{font-family:'Courier New',monospace;background:#0a0a0a;color:#e0e0e0;padding:16px}}
h1{{color:#f00;font-size:1.8em;margin-bottom:4px}}
.sub{{color:#888;font-size:.85em;margin-bottom:20px}}
.threat-banner{{background:{threat_color}22;border:2px solid {threat_color};border-radius:8px;padding:18px;text-align:center;margin-bottom:20px}}
.threat-banner .label{{color:#888;font-size:.8em;text-transform:uppercase;letter-spacing:2px}}
.threat-banner .level{{font-size:3em;font-weight:bold;color:{threat_color};margin:8px 0}}
.threat-banner .score{{color:#aaa;font-size:.9em}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;margin-bottom:20px}}
.card{{background:#111;border:1px solid #333;border-radius:8px;padding:16px}}
.card .label{{color:#888;font-size:.75em;text-transform:uppercase;letter-spacing:1px}}
.card .value{{font-size:1.8em;font-weight:bold;margin-top:6px}}
.card .detail{{color:#888;font-size:.8em;margin-top:4px}}
table{{width:100%;border-collapse:collapse;margin-top:8px;font-size:.82em}}
th,td{{padding:6px 8px;text-align:left;border-bottom:1px solid #222}}
th{{color:#f00;font-size:.7em;text-transform:uppercase}}
.dot{{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:4px}}
.dot.low{{background:#0f0}}.dot.medium{{background:#ff0}}.dot.high{{background:#f80}}.dot.critical{{background:#f00;animation:pulse 1s infinite}}
.dot.info{{background:#0ff}}.dot.error{{background:#f00}}.dot.warning{{background:#ff0}}.dot.alert{{background:#f00;animation:pulse .5s infinite}}
@keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.3}}}}
.section{{margin-bottom:24px}}
.section h2{{color:#f00;font-size:1.1em;margin-bottom:10px;border-bottom:1px solid #333;padding-bottom:6px}}
.footer{{margin-top:24px;padding-top:12px;border-top:1px solid #222;color:#555;font-size:.75em;text-align:center}}
.refresh{{color:#0ff;cursor:pointer}}
</style></head><body>
<h1>🛡️ Souran AI Security Dashboard v{VERSION}</h1>
<div class="sub">Real-time security monitoring • Auto-refresh: 10s • <span class="refresh" onclick="location.reload()">⟳</span></div>
<div class="threat-banner">
  <div class="label">Threat Level</div>
  <div class="level">{threat}</div>
  <div class="score">Score: {threat_score:.1f} | Blocked: {len(data['blocked_ips'])} | Failed Logins: {len(data['failed_logins'])} | Suspicious: {len(data['suspicious_ips'])}</div>
</div>
<div class="grid">
  <div class="card"><div class="label">Active Connections</div><div class="value">{tc}</div><div class="detail">Listening + established</div></div>
  <div class="card"><div class="label">Blocked IPs</div><div class="value">{len(data['blocked_ips'])}</div><div class="detail">{len(data['blocked_ips'][:20])} shown</div></div>
  <div class="card"><div class="label">Failed Logins</div><div class="value">{len(data['failed_logins'])}</div><div class="detail">Last 24h window</div></div>
  <div class="card"><div class="label">Suspicious IPs</div><div class="value" style="color:#f80">{len(data['suspicious_ips'])}</div><div class="detail">Cross-referenced</div></div>
  <div class="card"><div class="label">Disk Usage</div><div class="value">{data['sys_info'].get('disk_used','?')}</div><div class="detail">of {data['sys_info'].get('disk_total','?')}</div></div>
  <div class="card"><div class="label">Memory</div><div class="value">{data['sys_info'].get('mem_used','?')}</div><div class="detail">of {data['sys_info'].get('mem_total','?')}</div></div>
</div>
<div class="section"><h2>⚠️ Blocked IPs</h2><table><thead><tr><th>IP</th><th>Action</th><th>Rule</th></tr></thead><tbody>{blocked_rows}</tbody></table></div>
<div class="section"><h2>🔴 Failed Login Attempts</h2><table><thead><tr><th>Time</th><th>Source IP</th><th>User</th><th>Detail</th></tr></thead><tbody>{failed_rows}</tbody></table></div>
<div class="section"><h2>📡 Active Connections</h2><table><thead><tr><th></th><th>State</th><th>Local Address</th><th>Process</th></tr></thead><tbody>{conn_rows}</tbody></table></div>
<div class="section"><h2>🚨 Suspicious IPs</h2><table><thead><tr><th>IP</th><th>Flagged</th></tr></thead><tbody>{sus_rows}</tbody></table></div>
<div class="section"><h2>📋 Security Events</h2><table><thead><tr><th></th><th>Time</th><th>Event</th></tr></thead><tbody>{event_rows}</tbody></table></div>
<div class="footer">Souran AI Network Server v{VERSION} • Security Monitor • Port {PORT} • {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</div>
<script>setTimeout(()=>location.reload(),10000)</script></body></html>"""
    return html.encode('utf-8')

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        p = urlparse(self.path)
        if p.path == '/api/security':
            data = {"blocked_ips": collect_blocked_ips(), "failed_logins": collect_failed_logins(), "active_connections": collect_active_connections(), "suspicious_ips": collect_suspicious_ips(), "security_events": collect_security_events(), "sys_info": collect_disk_and_system(), "timestamp": datetime.utcnow().isoformat(), "version": VERSION, "total_connections": len(collect_active_connections())}
            self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers(); self.wfile.write(json.dumps(data).encode('utf-8'))
        elif p.path.startswith('/api/block'):
            query = p.query; ip_match = re.search(r'ip=(\S+)', query)
            if ip_match:
                ip = ip_match.group(1)
                try:
                    subprocess.run(['iptables','-A','INPUT','-s',ip,'-j','DROP'], capture_output=True, timeout=5)
                    self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers(); self.wfile.write(json.dumps({"status":"blocked","ip":ip}).encode('utf-8'))
                except Exception as e:
                    self.send_response(500); self.send_header('Content-Type','application/json'); self.end_headers(); self.wfile.write(json.dumps({"status":"error","error":str(e)}).encode('utf-8'))
            else:
                self.send_response(400); self.end_headers()
        else:
            self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.end_headers()
            self.wfile.write(build_html({"blocked_ips": [], "failed_logins": [], "active_connections": [], "suspicious_ips": [], "security_events": [], "sys_info": {}, "total_connections": 0, "timestamp": datetime.utcnow().isoformat(), "version": VERSION}))
    def log_message(self, f, *a): pass

if __name__ == '__main__':
    print(f"🛡️ Souran AI Security Dashboard v{VERSION} starting on port {PORT}...")
    http.server.HTTPServer(('0.0.0.0', PORT), Handler).serve_forever()
