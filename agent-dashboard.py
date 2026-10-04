#!/usr/bin/env python3
# Version: v5.1.0 | Souran AI Network Server
"""Souran AI Network Server - Agent Control Dashboard
Port 8082 - Agent bridges, tool management, and control interfaces
"""
import http.server, json, subprocess, urllib.parse, os, sys
from datetime import datetime
from pathlib import Path

VERSION = "5.1.0"
PORT = 8082
STATUS_FILE = "/run/souran-ai-status.json"

def get_agent_tools():
    """Discover available agent tools"""
    tools = []
    tool_categories = {
        'System': ['systemctl', 'journalctl', 'ip', 'ss', 'netstat'],
        'Files': ['read_file', 'write_file', 'patch'],
        'Network': ['dig', 'curl', 'wget', 'nmap'],
        'Process': ['ps', 'pgrep', 'pkill', 'top'],
        'Security': ['fail2ban-client', 'ufw', 'iptables']
    }
    
    for category, tool_list in tool_categories.items():
        for tool in tool_list:
            path = subprocess.run(['which', tool], capture_output=True, text=True)
            tools.append({
                'name': tool,
                'category': category,
                'executable': True if path.returncode == 0 else False,
                'path': path.stdout.strip() if path.returncode == 0 else None
            })
    return tools

def get_processes():
    """Get running processes"""
    procs = []
    try:
        r = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines()[1:21]:
            parts = line.split(None, 10)
            if len(parts) >= 11:
                procs.append({
                    'user': parts[0],
                    'pid': parts[1],
                    'cpu': parts[2],
                    'mem': parts[3],
                    'cmd': parts[10][:60]
                })
    except:
        pass
    return procs

def run_command(cmd):
    """Execute a shell command safely"""
    try:
        # Only allow specific safe commands
        allowed = ['status', 'check', 'init', 'logs', 'disk', 'memory', 'uptime']
        if cmd not in allowed:
            return {'error': f'Command not allowed. Allowed: {allowed}', 'output': '', 'exit_code': 1}
        
        r = subprocess.run(['/opt/souran-ai/souran-ai', cmd], capture_output=True, text=True, timeout=30)
        return {'output': r.stdout, 'error': r.stderr, 'exit_code': r.returncode}
    except Exception as e:
        return {'error': str(e), 'output': '', 'exit_code': 1}

def get_system_metrics():
    """Get system metrics"""
    metrics = {}
    try:
        r = subprocess.run(['uptime', '-p'], capture_output=True, text=True)
        metrics['uptime'] = r.stdout.strip()
    except:
        metrics['uptime'] = 'unknown'
    
    try:
        r = subprocess.run(['free', '-h'], capture_output=True, text=True)
        lines = r.stdout.strip().split('\n')
        if len(lines) >= 2:
            parts = lines[1].split()
            metrics['memory'] = {'used': parts[2] if len(parts) > 2 else '?', 
                                'total': parts[1] if len(parts) > 1 else '?'}
    except:
        metrics['memory'] = {'used': '?', 'total': '?'}
    
    try:
        r = subprocess.run(['df', '-h', '/'], capture_output=True, text=True)
        lines = r.stdout.strip().split('\n')
        if len(lines) >= 2:
            parts = lines[1].split()
            metrics['disk'] = {'used': parts[4] if len(parts) > 4 else '?', 
                              'total': parts[1] if len(parts) > 1 else '?'}
    except:
        metrics['disk'] = {'used': '?', 'total': '?'}
    
    return metrics

def build_html(tools, processes, metrics):
    metrics_html = f"""
<div class="card"><h3>Uptime</h3><div class="value">{metrics.get('uptime','?')}</div></div>
<div class="card"><h3>Memory</h3><div class="value">{metrics.get('memory',{}).get('used','?')} / {metrics.get('memory',{}).get('total','?')}</div></div>
<div class="card"><h3>Disk</h3><div class="value">{metrics.get('disk',{}).get('used','?')} / {metrics.get('disk',{}).get('total','?')}</div></div>
"""
    
    proc_rows = ''.join(f"<tr><td>{p['user']}</td><td>{p['pid']}</td><td>{p['cpu']}</td><td>{p['mem']}</td><td>{p['cmd']}</td></tr>" 
                       for p in processes) or "<tr><td colspan='5'>No processes found</td></tr>"
    
    return f"""<!DOCTYPE html><html><head>
<title>Souran Agent Control v{VERSION}</title>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0a0a15;color:#e0e0e0;padding:24px}}
h1{{font-size:1.6em;margin-bottom:8px;color:#0ff}}
.sub{{color:#888;margin-bottom:24px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:16px}}
.card{{background:#111;border:1px solid #222;border-radius:8px;padding:16px}}
.card h3{{color:#888;font-size:.75em;text-transform:uppercase;letter-spacing:1px}}
.card .value{{font-size:1.3em;font-weight:bold;margin-top:6px}}
table{{width:100%;border-collapse:collapse;margin-top:8px;font-size:.75em}}
th,td{{padding:6px 8px;text-align:left;border-bottom:1px solid #222}}
th{{color:#0ff}}
.code{{background:#020205;border:1px solid #222;border-radius:4px;padding:12px;overflow-x:auto}}
pre{{font-family:monospace;color:#a6e22c}}
button{{background:#0a3;color:#0f0;border:none;padding:8px 12px;border-radius:4px;cursor:pointer}}
button:hover{{background:#0a5}}
</style></head><body>
<h1>Souran Agent Control v{VERSION}</h1>
<div class="sub">Port {PORT} • <span onclick="location.reload()">⟳</span></div>

<div class="grid">{metrics_html}</div>

<h2 style="margin-top:24px;margin-bottom:12px;color:#ff6">Agent Tools</h2>
<div class="code">
<table><thead><tr><th>Tool</th><th>Category</th><th>Status</th></tr></thead><tbody>
{''.join(f"<tr><td>{t['name']}</td><td>{t['category']}</td><td>{'✓' if t['executable'] else '✗'}</td></tr>" for t in tools)}
</tbody></table>
</div>

<h2 style="margin-top:24px;margin-bottom:12px;color:#ff6">Quick Actions</h2>
<div style="display:flex;gap:8px;flex-wrap:wrap">
<button onclick="fetch('/api/exec?cmd=check').then(r=>r.json()).then(d=>alert(d.output))">Check Services</button>
<button onclick="fetch('/api/exec?cmd=status').then(r=>r.json()).then(d=>alert(d.output))">Show Status</button>
<button onclick="fetch('/api/exec?cmd=init').then(r=>r.json()).then(d=>alert('Init: '+d.output[:100]))">Init Services</button>
<button onclick="fetch('/api/exec?cmd=logs').then(r=>r.json()).then(d=>alert(d.output.slice(0,1000)))">View Logs</button>
</div>

<h2 style="margin-top:24px;margin-bottom:12px;color:#ff6">Top Processes</h2>
<div class="code"><table><thead><tr><th>User</th><th>PID</th><th>CPU</th><th>MEM</th><th>Command</th></tr></thead><tbody>{proc_rows}</tbody></table></div>

<footer style="margin-top:32px;padding-top:12px;border-top:1px solid #222;color:#555;font-size:.75em;text-align:center">
Souran AI Network Server v{VERSION} • Agent Control • Port {PORT}
</footer>
</body></html>"""

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        
        if path == '/api/tools':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(get_agent_tools(), indent=2).encode())
            return
        
        if path == '/api/metrics':
            metrics = get_system_metrics()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(metrics, indent=2).encode())
            return
        
        if path == '/api/processes':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(get_processes(), indent=2).encode())
            return
        
        if path == '/api/exec':
            cmd = urllib.parse.parse_qs(parsed.query).get('cmd', [''])[0]
            result = run_command(cmd)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result, indent=2).encode())
            return
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(build_html(get_agent_tools(), get_processes(), get_system_metrics()).encode())

    def log_message(self, format, *args):
        pass

if __name__ == '__main__':
    print(f"Souran Agent Control starting on port {PORT}...")
    http.server.HTTPServer(('0.0.0.0', PORT), Handler).serve_forever()