#!/usr/bin/env python3
# Version: v5.1.0 | Souran AI Network Server

import subprocess,json,time
from collections import defaultdict
from datetime import datetime,timezone
CONFIG={"ports":{8081:{"max_conn":10},8082:{"max_conn":10},8080:{"max_conn":5},53443:{"max_conn":20}},"check_interval":10,"log_file":"/var/log/souran-rate-limit.log","alert_threshold":3}
class RateLimiter:
    def __init__(self): self.blocked=set(); self.alerts=defaultdict(int)
    def check(self):
        try:
            r=subprocess.run(["ss","-tlnp"],capture_output=True,text=True,timeout=5)
            conns=defaultdict(lambda:defaultdict(int))
            for line in r.stdout.strip().split("\n"):
                p=line.split()
                if len(p)>=6 and ":" in p[4] and ":" in p[5]:
                    port=p[4].split(":")[-1]; ip=p[5].split(":")[0]
                    if ip not in ["*","::","0.0.0.0"]: conns[port][ip]+=1
            for port,lim in CONFIG["ports"].items():
                if port in conns:
                    for ip,c in conns[port].items():
                        if ip in self.blocked: continue
                        if c>lim["max_conn"]:
                            key=f"{ip}:{port}"; self.alerts[key]+=1
                            if self.alerts[key]>=CONFIG["alert_threshold"]:
                                subprocess.run(["iptables","-I","INPUT","-s",ip,"-p","tcp","--dport",str(port),"-j","DROP"],capture_output=True,timeout=5)
                                self.blocked.add(ip); self.log(f"BLOCKED {ip} on {port}")
        except Exception as e: self.log(f"Error: {e}")
    def log(self,m):
        ts=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        line=f"[{ts}] RATE-LIMIT: {m}\n"
        with open(CONFIG["log_file"],"a") as f: f.write(line)
        print(line.strip())
    def run(self):
        self.log("Rate Limiter started")
        while True: self.check(); time.sleep(CONFIG["check_interval"])
if __name__=="__main__": RateLimiter().run()
