#!/usr/bin/env python3
import sys
import json
import os

timestamp = sys.argv[1] if len(sys.argv) > 1 else ''
dns_status = sys.argv[2] if len(sys.argv) > 2 else ''
cloudflared_status = sys.argv[3] if len(sys.argv) > 3 else ''
tor_status = sys.argv[4] if len(sys.argv) > 4 else ''
watchdog_status = sys.argv[5] if len(sys.argv) > 5 else ''

status_file = '/run/souran-ai-status.json'
if not os.path.exists(status_file):
    data = {
        'service': 'Souran AI Network Server',
        'version': '5.2.0',
        'timestamp': '',
        'dns': '',
        'cloudflared': '',
        'tor': '',
        'watchdog': '',
        'ports': {'dnr': 53, 'api': 53443, 'admin': 8080, 'web': 8383, 'agent': 8082, 'doh': 8083, 'tor': 9050},
        'features': ['Recursive DNS', 'DNSSEC', 'DoT', 'DoH', 'Tor Bypass', 'Advanced Cache', 'Auto-Healing Watchdog', 'Zero-Block', 'Web Dashboard 8383', 'Agent Control 8082', 'DoH Server 8083', 'Neuro Analytics 8383']
    }
else:
    with open(status_file, 'r') as f:
        data = json.load(f)

data['timestamp'] = timestamp
data['dns'] = dns_status
data['cloudflared'] = cloudflared_status
data['tor'] = tor_status
data['watchdog'] = watchdog_status

with open(status_file, 'w') as f:
    json.dump(data, f, indent=2)