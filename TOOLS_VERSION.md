# Souran AI Network Server v5.1.0 — Tools Version Manifest

> Generated: 2026-09-26 | Release: v5.1.0

## Python Scripts (`/opt/souran-ai/`)

| Script | Version | Size |
|--------|---------|------|
| agent-investigate.py | v5.1.0 | 14,671B |
| auto-block.py | v5.1.0 | 3,529B |
| intrusion-detection.py | v5.1.0 | 3,941B |
| rate-limit.py | v5.1.0 | 1,997B |
| security-dashboard.py | v5.1.0 | 14,698B |

## Shell Scripts (`/opt/souran-ai/`)

| Script | Version | Size |
|--------|---------|------|
| auto-watchdog.sh | v5.1.0 | 6,583B |
| build-v5.sh | v5.1.0 | 5,104B |
| dashboard.sh | v5.1.0 | 1,117B |
| firewall.sh | v5.1.0 | 5,692B |
| install.sh | v5.1.0 | 2,402B |
| refresh-dns-token.sh | v5.1.0 | 1,088B |
| security.sh | v5.1.0 | 27,725B |

## Python Scripts (`/home/reza/souran-kb/scripts/`)

| Script | Version | Size |
|--------|---------|------|
| anti_compress.py | v1.3.3 | 156,413B |
| anti_compress_learn.py | v1.1.0 | 6,227B |
| anti_compress_pdf_reader.py | v1.1.0 | 17,506B |
| build_master_index.py | v1.1.0 | 12,671B |
| create_knowledge_docs.py | v1.1.0 | 7,953B |
| extract_urls_batch.py | v1.1.0 | 5,162B |
| fetch_cache.py | v1.1.0 | 5,402B |
| hermes_grow.py | v1.2.0 | 16,467B |
| hermes_grow_all.py | v2.1.0 | 25,254B |
| load_knowledge.py | v1.1.0 | 4,647B |
| mine_dnsrfc.py | v1.1.0 | 1,313B |
| sd_migrate.py | v1.1.0 | 9,609B |
| sd_migrate_packaging.py | v1.1.0 | 4,486B |
| souran_8082_dashboard.py | v1.1.0 | 6,411B |
| souran_8082_dashboard_html.py | v1.1.0 | 8,623B |
| souran_8082_routes.py | v1.1.0 | 4,837B |
| souran_8082_run.py | v1.1.0 | 1,049B |
| souran_8083_doh.py | v1.1.0 | 10,429B |

## Systemd Services (`/etc/systemd/system/`)

| Service | Version |
|---------|---------|
| souran-8082-dashboard.service | v5.1.0 |
| souran-8083-doh.service | v5.1.0 |
| souran-ai-watchdog.service | v5.1.0 |
| souran-ai.service | v5.1.0 |
| souran-auto-block.service | v5.1.0 |
| souran-backup.service | v5.1.0 |
| souran-dashboard.service | v5.1.0 |
| souran-dashboard-standalone.service | v5.1.0 |
| souran-dns.service | v5.1.0 |
| souran-ids.service | v5.1.0 |
| souran-iptables.service | v5.1.0 |
| souran-rate-limit.service | v5.1.0 |
| souran-watchdog.service | v5.1.0 |

## Versioning Scheme

- **v5.1.0**: Major Souran infrastructure release (systemd management, watchdog, ports)
- **v1.x.0**: Python tools in souran-kb/scripts/ (toolkit-level)
- **v1.3.3**: anti_compress.py (skill-managed, from universal-skills/anti-compression-engineering)
