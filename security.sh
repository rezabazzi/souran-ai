#!/bin/bash
#===============================================================================
# SOURAN AI NETWORK SERVER v5.1.0 - SECURITY HARDENING SUITE
#===============================================================================
set -eu

LOG="/var/log/souran-security.log"
F2B_CONF="/etc/fail2ban"
F2B_JAIL_D="$F2B_CONF/jail.d"
HTPASSWD_FILE="/etc/souran-ai/.htpasswd"
AUTH_CONFIG="/etc/souran-ai/auth.conf"
IDS_SCRIPT="/opt/souran-ai/intrusion-detection.py"
AUTO_BLOCK_SCRIPT="/opt/souran-ai/auto-block.py"
RATE_LIMIT_SCRIPT="/opt/souran-ai/rate-limit.py"

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] SECURITY: $1" | tee -a "$LOG"; }
check_root() { [[ $EUID -ne 0 ]] && { echo "ERROR: root required" >&2; exit 1; }; }

# SECTION 1: BASIC AUTH
setup_basic_auth() {
    log "=== Setting up Basic Auth ==="
    mkdir -p /etc/souran-ai
    [[ -z "${SOURAN_ADMIN_PASS:-}" ]] && SOURAN_ADMIN_PASS=$(openssl rand -hex 16)
    htpasswd_gen() { local u="$1" p="$2"; local h; h=$(openssl passwd -apr1 "$p" 2>/dev/null); echo "${u}:${h}"; }
    htpasswd_gen "souranadmin" "$SOURAN_ADMIN_PASS" > "$HTPASSWD_FILE"
    chmod 600 "$HTPASSWD_FILE"
    cat > "$AUTH_CONFIG" <<'CFG'
htpasswd_file = /etc/souran-ai/.htpasswd
realm = "Souran AI Network Server v5.1.0 - Restricted Access"
timeout = 3600
CFG
    create_auth_middleware
    create_secure_dashboards
    log "Basic auth complete"
}

create_auth_middleware() {
    cat > /opt/souran-ai/auth_middleware.py <<'PYEOF'
#!/usr/bin/env python3
import base64, os, subprocess
from http.server import BaseHTTPRequestHandler
HTPASSWD_FILE="/etc/souran-ai/.htpasswd"
REALM="Souran AI Network Server v5.1.0 - Restricted Access"
def load_users():
    users={}
    if not os.path.exists(HTPASSWD_FILE): return users
    with open(HTPASSWD_FILE) as f:
        for line in f:
            line=line.strip()
            if ':' in line:
                u,h=line.split(':',1); users[u]=h
    return users
def verify_password(u,p):
    users=load_users()
    if u not in users: return False
    try:
        r=subprocess.run(['openssl','passwd','-apr1',p],capture_output=True,text=True,timeout=5)
        return r.stdout.strip()==users[u]
    except: return False
class AuthHandler(BaseHTTPRequestHandler):
    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate',f'Basic realm="{REALM}"')
        self.send_header('Content-Type','text/html'); self.end_headers()
        self.wfile.write(b'<html><body><h1>401 Unauthorized</h1></body></html>')
    def check_auth(self):
        ah=self.headers.get('Authorization','')
        if not ah.startswith('Basic '): return False
        try:
            d=base64.b64decode(ah.split(' ')[1]).decode('utf-8')
            u,p=d.split(':',1); return verify_password(u,p)
        except: return False
    def log_message(self,f,*a):
        from datetime import datetime,timezone
        with open('/var/log/souran-security-audit.log','a') as lf:
            lf.write(f"{self.address_string()} - [{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}] {f%a}\n")
if __name__=='__main__': print("Auth module loaded.")
PYEOF
    chmod +x /opt/souran-ai/auth_middleware.py
}

create_secure_dashboards() {
    cat > /opt/souran-ai/secure-web-dashboard.py <<'PYEOF'
#!/usr/bin/env python3
import sys,base64,subprocess,time,json
from urllib.parse import urlparse
from http.server import HTTPServer
sys.path.insert(0,'/opt/souran-ai')
from auth_middleware import AuthHandler,REALM
class H(AuthHandler):
    def do_GET(self):
        if not self.check_auth(): self.do_AUTHHEAD(); return
        p=urlparse(self.path)
        if p.path=='/api/status':
            self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers()
            s={}
            for svc in ['dns','souran-unbound','cloudflared','tor@default','souran-ai-watchdog','dnsmasq','souran-ai']:
                r=subprocess.run(['systemctl','is-active',svc],capture_output=True,text=True); s[svc]=r.stdout.strip()
            try: dns_ip=subprocess.run(['dig','@127.0.0.1','google.com','+short'],capture_output=True,text=True,timeout=5).stdout.strip().split('\n')[0]
            except: dns_ip='FAILED'
            try: ub_ip=subprocess.run(['dig','@127.0.0.1','-p','5300','cloudflare.com','+short'],capture_output=True,text=True,timeout=5).stdout.strip().split('\n')[0]
            except: ub_ip='FAILED'
            self.wfile.write(json.dumps({"version":"4.3.1","status":"stable","dns":dns_ip,"unbound":ub_ip,"services":s,"timestamp":time.time()}).encode())
        elif p.path=='/api/logs':
            self.send_response(200);self.send_header('Content-Type','text/plain');self.end_headers()
            try: logs=subprocess.run(['tail','-20','/var/log/souran-ai.log'],capture_output=True,text=True,timeout=5).stdout
            except: logs='No logs'
            self.wfile.write(logs.encode())
        else:
            self.send_response(200);self.send_header('Content-Type','text/html');self.end_headers()
            self.wfile.write(b'''<!DOCTYPE html><html><head><title>Souran AI v5.1.0</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Courier New,monospace;background:#0a0a0a;color:#0f0;padding:20px}h1{color:#0ff;font-size:2em;margin-bottom:10px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:15px;margin-bottom:20px}.card{background:#111;border:1px solid #0f0;border-radius:8px;padding:18px}.card .label{color:#888;font-size:.8em;text-transform:uppercase}.card .value{font-size:1.4em;font-weight:bold;margin-top:5px}.card .value.ok{color:#0f0}.card .value.dead{color:#f00}table{width:100%;border-collapse:collapse}th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #222}th{color:#0ff;font-size:.8em;text-transform:uppercase}td.ok{color:#0f0}td.dead{color:#f00}.footer{margin-top:30px;padding-top:15px;border-top:1px solid #222;color:#555;font-size:.8em}</style></head><body>
<h1>&#128274; Souran AI Network Server v5.1.0</h1><div class="grid"><div class="card"><div class="label">Version</div><div class="value ok">4.3.1</div></div><div class="card"><div class="label">DNS</div><div class="value" id="dns">Checking...</div></div><div class="card"><div class="label">Unbound</div><div class="value" id="ub">Checking...</div></div></div>
<h2>Services</h2><div class="card"><table><thead><tr><th></th><th>Service</th><th>Status</th></tr></thead><tbody id="svcs"></tbody></table></div>
<div class="footer">&#128274; Authenticated | Souran AI v5.1.0</div>
<script>async function load(){const d=await fetch('/api/status').then(r=>r.json());document.getElementById('dns').textContent=d.dns;document.getElementById('dns').className='value '+(d.dns!=='FAILED'?'ok':'dead');document.getElementById('ub').textContent=d.unbound;document.getElementById('ub').className='value '+(d.unbound!=='FAILED'?'ok':'dead');let t='';for(let k in d.services)t+=`<tr><td><span class="bar ${d.services[k]==='active'?'ok':'dead'}"></span></td><td>${k}</td><td class="${d.services[k]}">${d.services[k]}</td></tr>`;document.getElementById('svcs').innerHTML=t;}load();setInterval(load,10000);</script></body></html>''')
if __name__=='__main__':
    HTTPServer(('0.0.0.0',8081),H).serve_forever()
PYEOF
    chmod +x /opt/souran-ai/secure-web-dashboard.py

    cat > /opt/souran-ai/secure-agent-dashboard.py <<'PYEOF'
#!/usr/bin/env python3
import sys,base64,subprocess,time,json
from urllib.parse import urlparse
from http.server import HTTPServer
sys.path.insert(0,'/opt/souran-ai')
from auth_middleware import AuthHandler,REALM
class H(AuthHandler):
    def do_GET(self):
        if not self.check_auth(): self.do_AUTHHEAD(); return
        p=urlparse(self.path)
        if p.path=='/api/agent':
            self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers()
            try: model=subprocess.run('grep -A1 "provider:" /home/reza/.hermes/config.yaml 2>/dev/null | head -2',shell=True,capture_output=True,text=True,timeout=5).stdout.strip()
            except: model='unknown'
            conns=subprocess.run(['ss','-tlnp'],capture_output=True,text=True,timeout=5).stdout.strip()
            self.wfile.write(json.dumps({"agent":"Souran AI","version":"4.3.1","status":"stable","model":model,"connections":conns.split('\n') if conns else [],"timestamp":time.time()}).encode())
        else:
            self.send_response(200);self.send_header('Content-Type','text/html');self.end_headers()
            self.wfile.write(b'''<!DOCTYPE html><html><head><title>Souran AI Agent v5.1.0</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Courier New,monospace;background:#000;color:#0ff;padding:20px}h1{color:#fff;font-size:2em}h2{color:#0ff;font-size:1em;margin:15px 0 8px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:20px}.card{background:#111;border:1px solid #0ff;border-radius:8px;padding:15px}.card .label{color:#888;font-size:.8em;text-transform:uppercase}.card .value{font-size:1.3em;font-weight:bold;color:#0ff;margin-top:5px}pre{background:#111;padding:10px;border-radius:4px;font-size:.8em;overflow-x:auto}.footer{margin-top:20px;padding-top:10px;border-top:1px solid #333;color:#555;font-size:.7em}</style></head><body>
<h1>&#128274; Souran AI Agent Control Panel v5.1.0</h1><div class="grid"><div class="card"><div class="label">Agent</div><div class="value">Souran AI</div></div><div class="card"><div class="label">Version</div><div class="value">4.3.1</div></div><div class="card"><div class="label">Status</div><div class="value">Stable</div></div></div>
<h2>Connections</h2><div class="card"><pre id="conns">Loading...</pre></div>
<div class="footer">&#128274; Authenticated | Autonomous 24/7</div>
<script>async function load(){const d=await fetch('/api/agent').then(r=>r.json());document.getElementById('conns').textContent=d.connections.join('\\n');}load();setInterval(load,5000);</script></body></html>''')
if __name__=='__main__':
    HTTPServer(('0.0.0.0',8082),H).serve_forever()
PYEOF
    chmod +x /opt/souran-ai/secure-agent-dashboard.py
}

# SECTION 2: FAIL2BAN
setup_fail2ban() {
    log "=== Setting up Fail2Ban ==="
    pgrep -x fail2ban-server >/dev/null 2>&1 || { systemctl start fail2ban 2>/dev/null || fail2ban-server -b 2>/dev/null || true; sleep 1; }
    cat > "$F2B_JAIL_D/souran-dashboards.conf" <<'F2BEOF'
[DEFAULT]
bantime=1h; findtime=10m; maxretry=5; backend=systemd; banaction=iptables-multiport
[souran-web-dashboard]
enabled=true; port=8081; filter=souran-auth-fail; logpath=/var/log/souran-security-audit.log; maxretry=3; bantime=2h; findtime=15m
[souran-agent-dashboard]
enabled=true; port=8082; filter=souran-auth-fail; logpath=/var/log/souran-security-audit.log; maxretry=3; bantime=2h; findtime=15m
[souran-admin-port]
enabled=true; port=8080; filter=souran-auth-fail; logpath=/var/log/souran-security-audit.log; maxretry=3; bantime=2h; findtime=15m
[souran-technitium-api]
enabled=true; port=53443; filter=souran-techitium-auth; logpath=/var/log/souran-ai.log; maxretry=5; bantime=1h; findtime=10m
[souran-ssh-bruteforce]
enabled=true; port=ssh; filter=sshd; logpath=/var/log/auth.log; maxretry=3; bantime=4h; findtime=10m
[recidive]
enabled=true; logpath=/var/log/fail2ban.log; banaction=%(banaction_allports)s; bantime=1w; findtime=1d; maxretry=3
F2BEOF
    cat > "$F2B_CONF/filter.d/souran-auth-fail.conf" <<'FILTER'
[Definition]
failregex=^.*Authentication failed.*client=<HOST>.*$
          ^.*401 Unauthorized.*client=<HOST>.*$
          ^.*Invalid credentials.*client=<HOST>.*$
FILTER
    cat > "$F2B_CONF/filter.d/souran-techitium-auth.conf" <<'FILTER'
[Definition]
failregex=^.*invalid-token.*$
          ^.*auth failed.*$
          ^.*401.*$
FILTER
    systemctl restart fail2ban 2>/dev/null || true
    fail2ban-client reload 2>/dev/null || true
    for jail in souran-web-dashboard souran-agent-dashboard souran-admin-port souran-technitium-api souran-ssh-bruteforce recidive; do
        fail2ban-client set "$jail" enable true 2>/dev/null || true
    done
    log "Fail2Ban setup complete"
}

# SECTION 3: RATE LIMITING
setup_rate_limiting() {
    log "=== Setting up Rate Limiting ==="
    iptables -I INPUT -p tcp --dport 8081 -m connlimit --connlimit-above 10 --connlimit-mask 32 -j DROP
    iptables -I INPUT -p tcp --dport 8082 -m connlimit --connlimit-above 10 --connlimit-mask 32 -j DROP
    iptables -I INPUT -p tcp --dport 8080 -m connlimit --connlimit-above 5 --connlimit-mask 32 -j DROP
    iptables -I INPUT -p tcp --dport 53443 -m connlimit --connlimit-above 20 --connlimit-mask 32 -j DROP
    iptables -I INPUT -p udp --dport 53 -m limit --limit 100/s --limit-burst 200 -j ACCEPT
    create_rate_limit_script
    log "Rate limiting configured"
}

create_rate_limit_script() {
    cat > "$RATE_LIMIT_SCRIPT" <<'PYEOF'
#!/usr/bin/env python3
import subprocess,json,time
from collections import defaultdict
from datetime import datetime,timezone
CONFIG={"ports":{8081:{"max_conn":10},8082:{"max_conn":10},8080:{"max_conn":5},53443:{"max_conn":20}},"check_interval":10,"log_file":"/var/log/souran-rate-limit.log","alert_threshold":3}
class RateLimiter:
    def __init__(self): self.blocked=set(); self.alerts=defaultdict(int)
    def check(self):
        try:
            r=subprocess.run(['ss','-tlnp'],capture_output=True,text=True,timeout=5)
            conns=defaultdict(lambda:defaultdict(int))
            for line in r.stdout.strip().split('\n'):
                p=line.split()
                if len(p)>=6 and ':' in p[4] and ':' in p[5]:
                    port=p[4].split(':')[-1]; ip=p[5].split(':')[0]
                    if ip not in ['*','::','0.0.0.0']: conns[port][ip]+=1
            for port,lim in CONFIG["ports"].items():
                if port in conns:
                    for ip,c in conns[port].items():
                        if ip in self.blocked: continue
                        if c>lim["max_conn"]:
                            key=f"{ip}:{port}"; self.alerts[key]+=1
                            if self.alerts[key]>=CONFIG["alert_threshold"]:
                                subprocess.run(['iptables','-I','INPUT','-s',ip,'-p','tcp','--dport',str(port),'-j','DROP'],capture_output=True,timeout=5)
                                self.blocked.add(ip); self.log(f"BLOCKED {ip} on {port}")
        except Exception as e: self.log(f"Error: {e}")
    def log(self,m):
        ts=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        line=f"[{ts}] RATE-LIMIT: {m}\n"
        with open(CONFIG["log_file"],'a') as f: f.write(line)
        print(line.strip())
    def run(self):
        self.log("Rate Limiter started")
        while True: self.check(); time.sleep(CONFIG["check_interval"])
if __name__=='__main__': RateLimiter().run()
PYEOF
    chmod +x "$RATE_LIMIT_SCRIPT"
}

# SECTION 4: INTRUSION DETECTION
setup_intrusion_detection() {
    log "=== Setting up IDS ==="
    cat > "$IDS_SCRIPT" <<'PYEOF'
#!/usr/bin/env python3
import subprocess,json,re,time,os
from datetime import datetime,timezone
from collections import defaultdict
CONFIG={"log_files":["/var/log/souran-ai.log","/var/log/souran-ai-watchdog.log","/var/log/souran-security-audit.log","/var/log/auth.log","/var/log/syslog","/var/log/fail2ban.log"],"check_interval":30,"alert_log":"/var/log/souran-ids-alerts.log","thresholds":{"failed_auths":5,"port_scan":10},"whitelist":["127.0.0.1","::1"]}
class IDS:
    def __init__(self): self.auth_count=defaultdict(int); self.blocked=set()
    def parse_logs(self,path):
        if not os.path.exists(path): return []
        try:
            with open(path) as f: return [l.strip() for l in f.readlines()[-100:]]
        except: return []
    def detect(self,entries):
        alerts=[]
        for entry in entries:
            for pat in [r"Failed password.*from (\d+\.\d+\.\d+\.\d+)",r"Invalid user.*from (\d+\.\d+\.\d+\.\d+)",r"authentication failure.*from (\d+\.\d+\.\d+\.\d+)"]:
                m=re.search(pat,entry)
                if m:
                    ip=m.group(1)
                    if ip not in CONFIG["whitelist"]:
                        self.auth_count[ip]+=1
                        sev="critical" if self.auth_count[ip]>=CONFIG["thresholds"]["failed_auths"] else "high"
                        alert={"timestamp":datetime.now(timezone.utc).isoformat(),"type":"auth_failure","ip":ip,"severity":sev}
                        alerts.append(alert)
                        if self.auth_count[ip]>=CONFIG["thresholds"]["failed_auths"]: self.block(ip)
        return alerts
    def detect_scans(self):
        alerts=[]
        try:
            r=subprocess.run(['ss','-tlnp'],capture_output=True,text=True,timeout=5)
            pc=defaultdict(set)
            for line in r.stdout.strip().split('\n'):
                p=line.split()
                if len(p)>=6 and ':' in p[4] and ':' in p[5]:
                    ip=p[5].split(':')[0]; port=p[4].split(':')[-1]
                    if ip not in ['*','::','0.0.0.0'] and not any(ip.startswith(x) for x in ['10.','192.168.','127.']): pc[ip].add(port)
            for ip,ports in pc.items():
                if len(ports)>=CONFIG["thresholds"]["port_scan"]:
                    alert={"timestamp":datetime.now(timezone.utc).isoformat(),"type":"port_scan","ip":ip,"ports":len(ports),"severity":"high"}
                    alerts.append(alert); self.block(ip)
        except: pass
        return alerts
    def block(self,ip):
        if ip in self.blocked: return
        try:
            subprocess.run(['iptables','-I','INPUT','-s',ip,'-j','DROP'],capture_output=True,timeout=5)
            self.blocked.add(ip)
            self.log_alert({"type":"auto_block","ip":ip,"reason":"intrusion_detected"})
        except Exception as e: self.log(f"Block failed: {e}")
    def log_alert(self,a):
        ts=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        with open(CONFIG["alert_log"],'a') as f: f.write(f"[{ts}] {json.dumps(a)}\n")
        print(f"[IDS ALERT] {json.dumps(a,indent=2)}")
    def log(self,m):
        ts=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        line=f"[{ts}] IDS: {m}\n"
        with open(CONFIG["alert_log"],'a') as f: f.write(line)
        print(line.strip())
    def run_check(self):
        alerts=[]
        for lf in CONFIG["log_files"]: alerts.extend(self.detect(self.parse_logs(lf)))
        alerts.extend(self.detect_scans())
        return alerts
    def run(self):
        self.log("IDS started")
        while True:
            try:
                a=self.run_check()
                if not a: self.log("No threats detected")
                time.sleep(CONFIG["check_interval"])
            except KeyboardInterrupt: self.log("IDS stopped"); break
            except Exception as e: self.log(f"Error: {e}"); time.sleep(5)
if __name__=='__main__': IDS().run()
PYEOF
    chmod +x "$IDS_SCRIPT"
    log "IDS configured"
}

# SECTION 5: SECURITY LOGGING
setup_security_logging() {
    log "=== Setting up Security Logging ==="
    mkdir -p /var/log/souran-security
    cat > /etc/rsyslog.d/souran-security.conf <<'RSYS'
:programname,contains,"souran-security" /var/log/souran-security-audit.log
:programname,contains,"souran-ids" /var/log/souran-ids-alerts.log
:programname,contains,"fail2ban" /var/log/fail2ban.log
:msg,contains,"FIREWALL-DROP" /var/log/souran-firewall.log
:programname,contains,"rate-limit" /var/log/souran-rate-limit.log
RSYS
    cat > /etc/logrotate.d/souran-security <<'LR'
/var/log/souran-security-audit.log /var/log/souran-ids-alerts.log /var/log/souran-firewall.log /var/log/souran-rate-limit.log /var/log/fail2ban.log
{
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        systemctl reload rsyslog 2>/dev/null || true
        fail2ban-client reload 2>/dev/null || true
    endscript
}
LR
    systemctl restart rsyslog 2>/dev/null || true
    log "Security logging configured"
}

# SECTION 6: AUTO-BLOCK
setup_auto_block() {
    log "=== Setting up Auto-Block ==="
    cat > "$AUTO_BLOCK_SCRIPT" <<'PYEOF'
#!/usr/bin/env python3
import subprocess,json,time,re
from datetime import datetime,timezone
from collections import defaultdict
CONFIG={"check_interval":60,"ban_duration":24,"max_score":10,"weights":{"failed_auth":2,"port_scan":5,"connection_flood":3,"recidive":8},"whitelist":["127.0.0.1","::1"]}
class AutoBlocker:
    def __init__(self): self.scores=defaultdict(int); self.history=defaultdict(list); self.banned={}
    def get_fail2ban_banned(self):
        banned=set()
        try:
            r=subprocess.run(['fail2ban-client','status'],capture_output=True,text=True,timeout=10)
            for line in r.stdout.split('\n'):
                if 'Jail list:' in line:
                    for jail in line.split(':')[1].strip().split(', '):
                        jail=jail.strip()
                        if not jail: continue
                        sr=subprocess.run(['fail2ban-client','status',jail],capture_output=True,text=True,timeout=5)
                        for sl in sr.stdout.split('\n'):
                            if 'Banned IP list:' in sl:
                                ips=sl.split(':')[1].strip()
                                if ips: banned.update(ips.split(', '))
        except: pass
        return banned
    def get_failures(self):
        failures=[]
        try:
            r=subprocess.run(['journalctl','--since','5 minutes ago','-p','warning','-u','sshd','--no-pager'],capture_output=True,text=True,timeout=10)
            for line in r.stdout.strip().split('\n'):
                m=re.search(r'from (\d+\.\d+\.\d+\.\d+)',line)
                if m: failures.append({"ip":m.group(1),"type":"ssh_auth"})
        except: pass
        return failures
    def score(self,ip):
        s=0
        for e in self.history[ip]: s+=CONFIG["weights"].get(e["type"],1)
        if self.history[ip] and len(self.history[ip])>0:
            age=(datetime.now(timezone.utc)-datetime.fromisoformat(self.history[ip][0]["timestamp"])).total_seconds()
            if age<3600: s*=1.5
        return s
    def ban(self,ip,reason,score):
        if ip in CONFIG["whitelist"]: return False
        try:
            subprocess.run(['iptables','-I','INPUT','-s',ip,'-j','DROP'],capture_output=True,timeout=5)
            for jail in ['souran-web-dashboard','souran-agent-dashboard','souran-admin-port']:
                subprocess.run(['fail2ban-client','set',jail,'banip',ip],capture_output=True,timeout=3)
            self.banned[ip]={"reason":reason,"score":score,"time":datetime.now(timezone.utc).isoformat()}
            self.log(f"BANNED {ip} | {reason} | score:{score}")
            return True
        except Exception as e: self.log(f"Ban failed {ip}: {e}"); return False
    def unban_expired(self):
        now=datetime.now(timezone.utc); expired=[]
        for ip,info in self.banned.items():
            bt=datetime.fromisoformat(info["time"])
            if (now-bt).total_seconds()>CONFIG["ban_duration"]*3600:
                expired.append(ip)
                try: subprocess.run(['iptables','-D','INPUT','-s',ip,'-j','DROP'],capture_output=True,timeout=5)
                except: pass
        for ip in expired: del self.banned[ip]
    def log(self,m):
        ts=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        line=f"[{ts}] AUTO-BLOCK: {m}\n"
        with open('/var/log/souran-auto-block.log','a') as f: f.write(line)
        print(line.strip())
    def monitor(self):
        while True:
            try:
                for f in self.get_failures():
                    ip=f["ip"]
                    if ip not in CONFIG["whitelist"]:
                        self.history[ip].append({"type":f["type"],"timestamp":datetime.now(timezone.utc).isoformat()})
                        if len(self.history[ip])>100: self.history[ip]=self.history[ip][-100:]
                        s=self.score(ip)
                        if s>=CONFIG["max_score"] and ip not in self.banned: self.ban(ip,f"score:{s}",s)
                self.unban_expired()
                time.sleep(CONFIG["check_interval"])
            except KeyboardInterrupt: self.log("Auto-Block stopped"); break
            except Exception as e: self.log(f"Error: {e}"); time.sleep(5)
    def run(self): self.log("Auto-Block started"); self.monitor()
if __name__=='__main__': AutoBlocker().run()
PYEOF
    chmod +x "$AUTO_BLOCK_SCRIPT"

    cat > "$F2B_JAIL_D/souran-recidive.conf" <<'F2BEOF'
[recidive]
enabled=true
logpath=/var/log/fail2ban.log
banaction=%(banaction_allports)s
bantime=1w
findtime=1d
maxretry=3
F2BEOF

    cat > /etc/systemd/system/souran-auto-block.service <<'SVCEOF'
[Unit]
Description=Souran AI Auto-Block Daemon
After=network.target fail2ban.service
Requires=fail2ban.service
[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/souran-ai/auto-block.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
[Install]
WantedBy=multi-user.target
SVCEOF

    cat > /etc/systemd/system/souran-ids.service <<'SVCEOF'
[Unit]
Description=Souran AI Intrusion Detection System
After=network.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/souran-ai/intrusion-detection.py
Restart=always
RestartSec=15
StandardOutput=journal
StandardError=journal
[Install]
WantedBy=multi-user.target
SVCEOF

    cat > /etc/systemd/system/souran-rate-limit.service <<'SVCEOF'
[Unit]
Description=Souran AI Rate Limiting Monitor
After=network.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/souran-ai/rate-limit.py
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal
[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload 2>/dev/null || true
    log "Auto-block system configured"
}

enable_services() {
    log "=== Enabling Services ==="
    systemctl enable fail2ban 2>/dev/null || true
    systemctl restart fail2ban 2>/dev/null || true
    systemctl enable souran-ids souran-rate-limit souran-auto-block 2>/dev/null || true
    systemctl start souran-ids souran-rate-limit souran-auto-block 2>/dev/null || true
    log "Services enabled"
}

main() {
    check_root
    log "=== SOURAN AI SECURITY HARDENING v5.1.0 ==="
    setup_basic_auth
    setup_fail2ban
    setup_rate_limiting
    setup_intrusion_detection
    setup_security_logging
    setup_auto_block
    enable_services
    log "Applying firewall rules..."
    bash /opt/souran-ai/firewall.sh apply 2>/dev/null || true
    log "=== SECURITY HARDENING COMPLETE ==="
    echo ""
    echo "============================================"
    echo "  SOURAN AI SECURITY HARDENING v5.1.0 COMPLETE"
    echo "============================================"
    echo ""
    echo "Components: Auth | Fail2Ban | RateLimit | IDS | Logging | AutoBlock | Firewall"
    echo "Dashboards: http://localhost:8081 (auth:souranadmin) | http://localhost:8082"
    echo ""
    echo "See $LOG for details."
}

case "${1:-}" in
    auth) setup_basic_auth ;;
    fail2ban) setup_fail2ban ;;
    rate-limit) setup_rate_limiting ;;
    ids) setup_intrusion_detection ;;
    logging) setup_security_logging ;;
    auto-block) setup_auto_block ;;
    enable) enable_services ;;
    status)
        echo "=== Security Status ==="
        fail2ban-client status 2>/dev/null || echo "fail2ban not running"
        echo "IDS: $(systemctl is-active souran-ids 2>/dev/null || echo 'not active')"
        echo "Rate Limit: $(systemctl is-active souran-rate-limit 2>/dev/null || echo 'not active')"
        echo "Auto-Block: $(systemctl is-active souran-auto-block 2>/dev/null || echo 'not active')"
        ;;
    *)
        main
        ;;
esac
