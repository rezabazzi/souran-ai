#!/usr/bin/env python3
# Version: v5.1.0 | Souran AI Network Server

"""
Souran AI Network Server v4.3.1 — Agent Investigation Tool
Scans logs, detects anomalies, tracks suspicious patterns
"""
import http.server, json, subprocess, time, re, os
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timedelta
from collections import defaultdict

VERSION = "4.3.1"
PORT = 8084
LOG_FILES = {
    "souran_ai": "/var/log/souran-ai.log", "souran_ai_watchdog": "/var/log/souran-ai-watchdog.log",
    "souran_watchdog": "/var/log/souran-watchdog/watchdog.log", "auth": "/var/log/auth.log",
    "sidecar": "/var/log/souran-sidecar.log", "souran_web": "/var/log/souran-web.log",
    "souran_agent": "/var/log/souran-agent.log",
}
PATTERNS = {
    "brute_force": re.compile(r'Failed password|Invalid user|authentication failure'),
    "sidecar_failure": re.compile(r'sidecar.*FAILED|sidecar.*fail'),
    "disk_critical": re.compile(r'Disk.*\d{2,}%|disk.*9[0-9]%'),
    "service_down": re.compile(r'(inactive|FAILED|not found|could not start)'),
    "dns_failure": re.compile(r'DNS.*FAIL|resolve.*failed|dig.*FAILED|DNS.*error'),
    "tor_breach": re.compile(r'tor.*fail|tor.*down|Tor.*inactive|Tor.*ERROR'),
    "watchdog_alert": re.compile(r'ALERT|CRITICAL|EMERGENCY'),
    "port_scan": re.compile(r'port.*scan|SYN.*flood|connection.*flood'),
    "intrusion": re.compile(r'intrusion|breach|unauthorized|access denied'),
    "iptables_block": re.compile(r'iptables.*BLOCK|DROP.*REJECT|iptables.*rule'),
}

def scan_log_file(logpath, max_lines=200):
    events = []
    try:
        r = subprocess.run(['tail', f'-{max_lines}', logpath], capture_output=True, text=True, timeout=10)
        for line in r.stdout.splitlines():
            if line.strip(): events.append({"timestamp": datetime.utcnow().isoformat(), "line": line.strip()})
    except Exception: pass
    return events

def detect_anomalies():
    anomalies = []; pattern_hits = defaultdict(list)
    for name, path in LOG_FILES.items():
        events = scan_log_file(path)
        for event in events:
            line = event['line']
            for pat_name, pat in PATTERNS.items():
                if pat.search(line): pattern_hits[pat_name].append({"source": name, "timestamp": event['timestamp'], "line": line[:200]})
    for pat_name, hits in pattern_hits.items():
        severity = "LOW"
        if pat_name in ('tor_breach','intrusion','watchdog_alert','brute_force'): severity = "HIGH"
        elif pat_name in ('sidecar_failure','disk_critical','dns_failure','port_scan'): severity = "MEDIUM"
        anomalies.append({"type": pat_name, "severity": severity, "count": len(hits), "hits": hits[:10], "first_seen": hits[0]['timestamp'] if hits else "N/A", "last_seen": hits[-1]['timestamp'] if hits else "N/A"})
    return sorted(anomalies, key=lambda a: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(a['severity'],4))

def track_suspicious_patterns():
    ip_activity = defaultdict(lambda: {"count":0,"sources":set(),"types":set(),"lines":[]})
    for name, path in LOG_FILES.items():
        try:
            r = subprocess.run(['tail','-200',path], capture_output=True, text=True, timeout=10)
            for line in r.stdout.splitlines():
                ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                users = re.findall(r'for (\w+)', line) + re.findall(r'user=(\w+)', line)
                for ip in ips:
                    if ip.startswith('127.') or ip == '0.0.0.0': continue
                    ip_activity[ip]['count'] += 1; ip_activity[ip]['sources'].add(name)
                    for user in users: ip_activity[ip]['types'].add(f'user:{user}')
                    ip_activity[ip]['lines'].append(line.strip()[:120])
        except Exception: pass
    suspicious = []
    for ip, activity in ip_activity.items():
        risk_score = activity['count']
        if len(activity['sources']) > 1: risk_score += 10
        if any('Failed' in l or 'Invalid' in l for l in activity['lines']): risk_score += 15
        if risk_score > 5:
            suspicious.append({"ip": ip, "count": activity['count'], "sources": sorted(activity['sources']), "types": sorted(activity['types'])[:5], "risk_score": risk_score, "sample_lines": activity['lines'][:3]})
    return sorted(suspicious, key=lambda x: x['risk_score'], reverse=True)[:20]

def get_service_status():
    services = {}
    for svc in ['dns','souran-unbound','souran-watchdog','souran-ai-watchdog','cloudflared','tor@default','dnsmasq','souran-ai','sidecar']:
        try:
            r = subprocess.run(['systemctl','is-active',svc], capture_output=True, text=True, timeout=5)
            services[svc] = r.stdout.strip()
        except Exception: services[svc] = "unknown"
    return services

def get_network_topology():
    topo = {"listening": [], "established": []}
    try:
        r = subprocess.run(['ss','-tlnp'], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4: topo['listening'].append({"addr": parts[3], "proc": parts[4].split('"')[1] if '"' in parts[4] else "unknown"})
    except Exception: pass
    try:
        r = subprocess.run(['ss','-tnp'], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines()[1:]:
            if 'ESTAB' in line: topo['established'].append({"addr": parts[4] if len(parts) > 4 else "?", "proc": parts[5].split('"')[1] if '"' in parts[5] else "unknown"})
    except Exception: pass
    return topo

def generate_investigation_report():
    anomalies = detect_anomalies(); suspicious = track_suspicious_patterns(); services = get_service_status()
    high_count = sum(1 for a in anomalies if a['severity'] == 'HIGH')
    medium_count = sum(1 for a in anomalies if a['severity'] == 'MEDIUM')
    low_count = sum(1 for a in anomalies if a['severity'] == 'LOW')
    known_issues = []
    try:
        r = subprocess.run(['grep','-h','ERROR.*even|FAILED.*after|consecutive failures','/var/log/souran-watchdog/watchdog.log'], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines()[-10:]: known_issues.append(line.strip()[:150])
    except Exception: pass
    return {"version": VERSION, "timestamp": datetime.utcnow().isoformat(), "summary": {"total_anomalies": len(anomalies), "high_severity": high_count, "medium_severity": medium_count, "low_severity": low_count, "suspicious_ips": len(suspicious), "services_checked": len(services)}, "anomalies": anomalies, "suspicious_ips": suspicious, "services": services, "network_topology": get_network_topology(), "known_issues": known_issues, "recommendations": generate_recommendations(anomalies, suspicious)}

def generate_recommendations(anomalies, suspicious):
    recs = []
    for a in anomalies:
        if a['type'] == 'brute_force': recs.append({"action":"BLOCK","target":a['type'],"detail":"Consider enabling fail2ban for SSH protection","priority":"HIGH"})
        elif a['type'] == 'tor_breach': recs.append({"action":"RESTART","target":"tor@default","detail":"Tor service appears down — restore censorship bypass","priority":"HIGH"})
        elif a['type'] == 'sidecar_failure': recs.append({"action":"HEAL","target":"sidecar","detail":"Sidecar has failed repeatedly — check port 9192","priority":"MEDIUM"})
        elif a['type'] == 'disk_critical': recs.append({"action":"CLEANUP","target":"disk","detail":"Disk usage critical — purge old logs and cache","priority":"HIGH"})
        elif a['type'] == 'dns_failure': recs.append({"action":"CHECK","target":"dns","detail":"DNS resolution failing — restart unbound/technitium","priority":"HIGH"})
    for s in suspicious:
        if s['risk_score'] > 20: recs.append({"action":"INVESTIGATE","target":s['ip'],"detail":f"High-risk IP with {s['count']} events across {len(s['sources'])} sources","priority":"HIGH"})
    if not recs: recs.append({"action":"OK","target":"system","detail":"No critical recommendations — all systems nominal","priority":"LOW"})
    return recs

def build_html(report):
    sev_colors = {"HIGH":"#f00","MEDIUM":"#f80","LOW":"#ff0","OK":"#0f0"}
    anomaly_rows = ''
    for a in report['anomalies']:
        color = sev_colors.get(a['severity'],'#888')
        hits_str = ''.join(f"<div class='hit'>{h['timestamp'][:19]} [{h['source']}] {h['line'][:80]}</div>" for h in a['hits'][:3])
        anomaly_rows += f"""<tr><td><span class="dot {a['severity'].lower()}" style="background:{color}"></span></td><td><strong>{a['type']}</strong></td><td style="color:{color}">{a['severity']}</td><td>{a['count']}</td><td>{a['first_seen'][:19]}</td><td>{hits_str}</td></tr>"""
    sus_rows = ''
    for s in report['suspicious_ips']:
        color = '#f00' if s['risk_score'] > 20 else '#f80' if s['risk_score'] > 10 else '#ff0'
        sus_rows += f"""<tr><td><code>{s['ip']}</code></td><td style="color:{color};font-weight:bold">{s['risk_score']}</td><td>{s['count']}</td><td>{', '.join(s['sources'])}</td><td>{', '.join(s['types'][:3])}</td></tr>"""
    svc_rows = ''
    for svc, status in report['services'].items():
        color = '#0f0' if status == 'active' else '#f00' if status in ('failed','inactive') else '#ff0'
        svc_rows += f"<tr><td>{svc}</td><td style='color:{color}'>{status}</td></tr>"
    recs = ''
    for r_ in report['recommendations']:
        color = sev_colors.get(r_['priority'],'#888')
        recs += f"""<div class="rec" style="border-left-color:{color}"><span class="action" style="color:{color}">{r_['action']}</span>: {r_['detail']} <span class="target">[{r_['target']}]</span></div>"""
    known_issues = ''.join(f"<div class='issue'>{i}</div>" for i in report['known_issues']) or "<div class='issue'>No known issues</div>"
    html = f"""<!DOCTYPE html><html><head><title>Souran AI Agent Investigator v{VERSION}</title>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{{font-family:'Courier New',monospace;background:#0a0a0a;color:#e0e0e0;padding:16px}}
h1{{color:#0ff;font-size:1.8em;margin-bottom:4px}}
.sub{{color:#888;font-size:.85em;margin-bottom:20px}}
.summary{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:20px}}
.stat{{background:#111;border:1px solid #333;border-radius:8px;padding:14px;text-align:center}}
.stat .num{{font-size:2.2em;font-weight:bold}}
.stat .lbl{{color:#888;font-size:.75em;text-transform:uppercase;margin-top:4px}}
.stat.high .num{{color:#f00}}.stat.medium .num{{color:#f80}}.stat.low .num{{color:#ff0}}
.section{{margin-bottom:24px}}
.section h2{{color:#0ff;font-size:1.1em;margin-bottom:10px;border-bottom:1px solid #333;padding-bottom:6px}}
table{{width:100%;border-collapse:collapse;font-size:.82em}}
th,td{{padding:6px 8px;text-align:left;border-bottom:1px solid #222}}
th{{color:#0ff;font-size:.7em;text-transform:uppercase}}
.dot{{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:4px}}
.dot.high{{background:#f00}}.dot.medium{{background:#f80}}.dot.low{{background:#ff0}}.dot.info{{background:#0ff}}
.hit{{background:#1a1a1a;padding:4px 8px;margin:2px 0;border-radius:3px;font-size:.78em;color:#aaa}}
.rec{{background:#111;border-left:3px solid #0ff;padding:8px 12px;margin:6px 0;border-radius:0 4px 4px 0;font-size:.85em}}
.action{{font-weight:bold;text-transform:uppercase;font-size:.8em}}
.issue{{background:#1a1a1a;padding:6px 10px;margin:3px 0;border-radius:3px;font-size:.8em;color:#f80}}
.refresh{{color:#0ff;cursor:pointer}}
.footer{{margin-top:24px;padding-top:12px;border-top:1px solid #222;color:#555;font-size:.75em;text-align:center}}
</style></head><body>
<h1>🔍 Souran AI Agent Investigator v{VERSION}</h1>
<div class="sub">Log analysis & anomaly detection • Auto-refresh: 15s • <span class="refresh" onclick="location.reload()">⟳</span></div>
<div class="summary">
  <div class="stat"><div class="num">{report['summary']['total_anomalies']}</div><div class="lbl">Anomalies</div></div>
  <div class="stat high"><div class="num">{report['summary']['high_severity']}</div><div class="lbl">High Severity</div></div>
  <div class="stat medium"><div class="num">{report['summary']['medium_severity']}</div><div class="lbl">Medium</div></div>
  <div class="stat low"><div class="num">{report['summary']['low_severity']}</div><div class="lbl">Low</div></div>
  <div class="stat"><div class="num">{report['summary']['suspicious_ips']}</div><div class="lbl">Suspicious IPs</div></div>
  <div class="stat"><div class="num">{report['summary']['services_checked']}</div><div class="lbl">Services</div></div>
</div>
<div class="section"><h2>⚡ Anomaly Detection</h2><table><thead><tr><th></th><th>Pattern</th><th>Severity</th><th>Count</th><th>First Seen</th><th>Evidence</th></tr></thead><tbody>{anomaly_rows}</tbody></table></div>
<div class="section"><h2>🎯 Suspicious IP Activity</h2><table><thead><tr><th>IP</th><th>Risk</th><th>Events</th><th>Sources</th><th>Types</th></tr></thead><tbody>{sus_rows}</tbody></table></div>
<div class="section"><h2>⚙️ Service Status</h2><table><thead><tr><th>Service</th><th>Status</th></tr></thead><tbody>{svc_rows}</tbody></table></div>
<div class="section"><h2>📋 Known Issues</h2>{known_issues}</div>
<div class="section"><h2>💡 Recommendations</h2>{recs}</div>
<div class="footer">Souran AI Network Server v{VERSION} • Agent Investigator • Port {PORT} • {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</div>
<script>setTimeout(()=>location.reload(),15000)</script></body></html>"""
    return html.encode('utf-8')

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        p = urlparse(self.path)
        if p.path == '/api/investigate':
            report = generate_investigation_report()
            self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers(); self.wfile.write(json.dumps(report).encode('utf-8'))
        elif p.path == '/api/suspicious':
            data = track_suspicious_patterns()
            self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers(); self.wfile.write(json.dumps(data).encode('utf-8'))
        else:
            self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.end_headers(); self.wfile.write(build_html(generate_investigation_report()))
    def log_message(self, f, *a): pass

if __name__ == '__main__':
    print(f"🔍 Souran AI Agent Investigator v{VERSION} starting on port {PORT}...")
    http.server.HTTPServer(('0.0.0.0', PORT), Handler).serve_forever()
