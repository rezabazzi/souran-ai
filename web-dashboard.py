#!/usr/bin/env python3
# Version: v5.1.0 | Souran AI Network Server
"""Souran AI Network Server - Web Dashboard
Port 8081 - Web UI for DNS management, monitoring, and configuration
"""
import http.server, json, subprocess, urllib.parse
from datetime import datetime
import os

VERSION = "5.1.0"
PORT = 8081
STATUS_FILE = "/run/souran-ai-status.json"

def get_system_info():
    try:
        with open(STATUS_FILE) as f:
            return json.load(f)
    except:
        return {"dns": "unknown", "tor": "unknown", "cloudflared": "unknown"}

def get_dns_stats():
    stats = {"queries": 0, "cache_hits": 0, "cache_misses": 0}
    try:
        r = subprocess.run(['systemctl', 'is-active', 'souran-dns'], capture_output=True, text=True, timeout=3)
        stats['dns_active'] = r.stdout.strip() == 'active'
    except:
        stats['dns_active'] = False
    return stats

def get_port_status(port):
    try:
        r = subprocess.run(['ss', '-tlnp'], capture_output=True, text=True, timeout=3)
        return f':{port}' in r.stdout
    except:
        return False

def build_html(system_info, dns_stats):
    ports = system_info.get('ports', {})
    dns_status = "✓ Active" if dns_stats.get('dns_active', False) else "✗ Inactive"
    
    return f"""<!DOCTYPE html><html><head>
<title>Souran AI Network Server v{VERSION} - Web Dashboard</title>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0a0a15;color:#e0e0e0;padding:24px}}
h1{{font-size:1.6em;margin-bottom:8px;color:#0ff}}
.sub{{color:#888;margin-bottom:24px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px}}
.card{{background:#111;border:1px solid #222;border-radius:8px;padding:16px}}
.card h3{{color:#888;font-size:.8em;text-transform:uppercase;letter-spacing:1px}}
.card .value{{font-size:1.6em;font-weight:bold;margin-top:8px;color:#0ff}}
.status{{display:inline-block;padding:4px 8px;border-radius:4px;font-size:.7em}}
.status.ok{{background:#0a3 color:#0f0}}
.status.error{{background:#300;color:#f44}}
pre{{background:#020205;color:#8af;color:#a6e22c;font-family:monospace;font-size:12px;overflow-x:auto;white-space:pre-wrap}}
.code{{background:#020205;border:1px solid #222;border-radius:4px;padding:12px;overflow-x:auto}}
</style></head><body>
<h1>Souran AI Network Server v{VERSION}</h1>
<div class="sub">Web Dashboard • <span onclick="location.reload()">⟳</span></div>

<div class="grid">
<div class="card"><h3>DNS Resolver</h3><div class="value">{dns_status}</div></div>
<div class="card"><h3>Port 53 DNS</h3><div class="value">{'✓' if get_port_status(53) else '✗'} Open</div></div>
<div class="card"><h3>Port 8082 Agent</h3><div class="value">{'✓' if get_port_status(8082) else '✗'} Open</div></div>
<div class="card"><h3>Tor Proxy</h3><div class="value">{'✓' if system_info.get('tor')=='active' else '✗'}</div></div>
</div>

<h2 style="margin-top:24px;margin-bottom:12px;color:#0ff">Actions</h2>
<div class="code">
<div style="display:flex;gap:8px;flex-wrap:wrap">
<button onclick="fetch('/api/check').then(r=>r.json()).then(d=>alert(JSON.stringify(d,none,2)))">Check Services</button>
<button onclick="fetch('/api/status').then(r=>r.json()).then(d=>alert(JSON.stringify(d,none,2)))">Show Status</button>
<button onclick="location.reload()">Refresh</button>
</div>
</div>

<div style="margin-top:24px"><h2 style="margin-bottom:12px;color:#0ff">Service Commands</h2>
<pre>
# Initialize all services
/opt/souran-ai/souran-ai init

# View status
/opt/souran-ai/souran-ai status

# Check services
/opt/souran-ai/souran-ai check

# Restart all
/opt/souran-ai/souran-ai restart

# Stop all
/opt/souran-ai/souran-ai stop
</pre>
</div>

<div style="margin-top:24px"><h2 style="margin-bottom:12px;color:#0ff">Agent Control (Port 8082)</h2>
<pre>
# Access agent dashboard
Open: http://localhost:8082/

# Agent tools available:
- Tool discovery & execution
- Shell command execution  
- File operations
- System monitoring
- Process management
</pre>
</div>

<footer style="margin-top:32px;padding-top:12px;border-top:1px solid #222;color:#555;font-size:.75em;text-align:center">
Souran AI Network Server v{VERSION} • Web Dashboard • Port {PORT} • Zone 53
</footer>
</body></html>""".replace('none,2)', 'null,2)')

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        
        if path == '/api/status':
            system_info = get_system_info()
            data = {"system": system_info, "dns": get_dns_stats(), "timestamp": datetime.utcnow().isoformat()}
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(data, indent=2).encode())
            return
        
        if path == '/api/check':
            try:
                r = subprocess.run(['/opt/souran-ai/souran-ai', 'check'], capture_output=True, text=True, timeout=10)
                result = {"output": r.stdout, "error": r.stderr, "exit_code": r.returncode}
            except Exception as e:
                result = {"error": str(e), "output": "", "exit_code": 1}
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result, indent=2).encode())
            return
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        system_info = get_system_info()
        self.wfile.write(build_html(system_info, get_dns_stats()).encode())

    def log_message(self, format, *args):
        pass

if __name__ == '__main__':
    print(f"Souran AI Web Dashboard starting on port {PORT}...")
    http.server.HTTPServer(('0.0.0.0', PORT), Handler).serve_forever()