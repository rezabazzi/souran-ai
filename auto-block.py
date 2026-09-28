#!/usr/bin/env python3
# Version: v5.1.0 | Souran AI Network Server

import subprocess,json,time,re
from datetime import datetime,timezone
from collections import defaultdict
CONFIG={"check_interval":60,"ban_duration":24,"max_score":10,"weights":{"failed_auth":2,"port_scan":5,"connection_flood":3,"recidive":8},"whitelist":["127.0.0.1","::1"]}
class AutoBlocker:
    def __init__(self): self.scores=defaultdict(int); self.history=defaultdict(list); self.banned={}
    def get_failures(self):
        failures=[]
        try:
            r=subprocess.run(["journalctl","--since","5 minutes ago","-p","warning","-u","sshd","--no-pager"],capture_output=True,text=True,timeout=10)
            for line in r.stdout.strip().split("\n"):
                m=re.search(r"from (\d+\.\d+\.\d+\.\d+)",line)
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
            subprocess.run(["iptables","-I","INPUT","-s",ip,"-j","DROP"],capture_output=True,timeout=5)
            for jail in ["souran-web-dashboard","souran-agent-dashboard","souran-admin-port"]:
                subprocess.run(["fail2ban-client","set",jail,"banip",ip],capture_output=True,timeout=3)
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
                try: subprocess.run(["iptables","-D","INPUT","-s",ip,"-j","DROP"],capture_output=True,timeout=5)
                except: pass
        for ip in expired: del self.banned[ip]
    def log(self,m):
        ts=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        line=f"[{ts}] AUTO-BLOCK: {m}\n"
        with open("/var/log/souran-auto-block.log","a") as f: f.write(line)
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
if __name__=="__main__": AutoBlocker().run()
