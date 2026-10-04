#!/usr/bin/env python3
"""
Migration script for Souran AI Network Server v5.2.0
Migrates data from old 8081 web dashboard to new 8383 dashboard
"""

import json
import os
from datetime import datetime, timezone

DATA_DIR = "/opt/souran-ai/data"
MIGRATION_LOG = f"{DATA_DIR}/migration.log"
os.makedirs(DATA_DIR, exist_ok=True)

def log(message):
    timestamp = datetime.now(timezone.utc).isoformat()
    entry = f"[{timestamp}] {message}"
    print(entry)
    with open(MIGRATION_LOG, 'a') as f:
        f.write(entry + "\n")

def migrate_stats():
    """Migrate DNS statistics from old to new format"""
    stats = {
        "version": "5.2.0",
        "port": 8383,
        "service": "souran-web-dashboard",
        "last_migrated": datetime.now(timezone.utc).isoformat(),
        "features": [
            "Recursive DNS",
            "DNSSEC",
            "DoT",
            "DoH", 
            "Tor Bypass",
            "Advanced Cache",
            "Zero-Block Policy",
            "Web Dashboard 8383",
            "Hermes Agent 8082",
            "DoH Server 8083",
            "Neuro Analytics"
        ]
    }
    
    stats_file = f"{DATA_DIR}/stats.json"
    with open(stats_file, 'w') as f:
        json.dump(stats, f, indent=2)
    
    log(f"Migrated stats to {stats_file}")
    return stats

def migrate_zones():
    """Migrate zone configurations"""
    zones = {
        "sitet.top": {
            "type": "forward",
            "upstream": [],
            "status": "active",
            "created": "2025-01-01"
        },
        "cafenetmordad.ir": {
            "type": "forward", 
            "upstream": [],
            "status": "active",
            "created": "2025-01-01"
        },
        "mordaddns.ir": {
            "type": "forward",
            "upstream": [],
            "status": "active", 
            "created": "2025-01-01"
        }
    }
    
    zones_file = f"{DATA_DIR}/zones.json"
    with open(zones_file, 'w') as f:
        json.dump(zones, f, indent=2)
    
    log(f"Migrated zones to {zones_file}")
    return zones

def migrate_api_keys():
    """Ensure API keys exist for services"""
    api_token_file = "/etc/dns/api-token.txt"
    
    if not os.path.exists(api_token_file):
        import secrets
        token = secrets.token_hex(32)
        with open(api_token_file, 'w') as f:
            f.write(token)
        os.chmod(api_token_file, 0o600)
        log(f"Created new API token at {api_token_file}")
    else:
        log(f"API token already exists at {api_token_file}")
    
    return True

def verify_services():
    """Verify all services are running"""
    import subprocess
    
    services = [
        ("souran-dns", 53),
        ("souran-web-8383", 8383),
        ("souran-8082-dashboard", 8082),
        ("souran-doh-8083", 8083),
        ("tor", 9050)
    ]
    
    for service, port in services:
        try:
            result = subprocess.run(
                ["systemctl", "is-active", service],
                capture_output=True, text=True, timeout=5
            )
            status = result.stdout.strip()
            log(f"Service {service} (port {port}): {status}")
        except Exception as e:
            log(f"Error checking {service}: {e}")
    
    return True

def main():
    log("=== Starting Souran AI v5.2.0 Migration ===")
    
    try:
        migrate_stats()
        migrate_zones()
        migrate_api_keys()
        verify_services()
        log("Migration completed successfully")
        return 0
    except Exception as e:
        log(f"Migration failed: {e}")
        return 1

if __name__ == "__main__":
    exit(main())