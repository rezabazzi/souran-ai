#!/usr/bin/env python3
# Version: v5.1.0 | Souran AI Network Server

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
            r=subprocess.run(["ss","-tlnp"],capture_output=True,text=True,timeout=5)
            pc=defaultdict(set)
            for line in r.stdout.strip().split("\n"):
                p=line.split()
                if len(p)>=6 and ":" in p[4] and ":" in p[5]:
                    ip=p[5].split(":")[0]; port=p[4].split(":")[-1]
                    if ip not in ["*","::","0.0.0.0"] and not any(ip.startswith(x) for x in ["10.","192.168.","127."]): pc[ip].add(port)
            for ip,ports in pc.items():
                if len(ports)>=CONFIG["thresholds"]["port_scan"]:
                    alert={"timestamp":datetime.now(timezone.utc).isoformat(),"type":"port_scan","ip":ip,"ports":len(ports),"severity":"high"}
                    alerts.append(alert); self.block(ip)
        except: pass
        return alerts
    def block(self,ip):
        if ip in self.blocked: return
        try:
            subprocess.run(["iptables","-I","INPUT","-s",ip,"-j","DROP"],capture_output=True,timeout=5)
            self.blocked.add(ip)
            self.log_alert({"type":"auto_block","ip":ip,"reason":"intrusion_detected"})
        except Exception as e: self.log(f"Block failed: {e}")
    def log_alert(self,a):
        ts=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with open(CONFIG["alert_log"],"a") as f: f.write(f"[{ts}] {json.dumps(a)}\n")
        print(f"[IDS ALERT] {json.dumps(a,indent=2)}")
    def log(self,m):
        ts=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        line=f"[{ts}] IDS: {m}\n"
        with open(CONFIG["alert_log"],"a") as f: f.write(line)
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
if __name__=="__main__": IDS().run()
