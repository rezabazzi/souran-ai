# Souran AI Network Server v5.2.0 - Status Report
**Generated:** 2026-09-30

## Service Status

| Port | Service | Status | Version | Description |
|------|---------|--------|---------|-------------|
| 53 | DNS Resolver | Active | Technitium v15.4 | Recursive DNS with Tor bypass |
| 8080 | Technitium Admin | Active | v15.4 | DNS admin interface (cached) |
| 8082 | Hermes Agent | Active | 2.2.0 | Agent control dashboard (your tools) |
| 8083 | DoH Proxy | Active | 1.0.0 | DNS-over-HTTPS for users |
| 8383 | Web Dashboard | Active | 5.2.0 | Neuro analytics dashboard |
| 9050 | Tor Proxy | Active | SOCKS5 | Censorship bypass |

## Dashboards

### Web Dashboard (Port 8383)
- Modern dark theme with gradient accents
- Tabbed interface: Overview, DNS Settings, Zones, Stats, Logs
- Real-time statistics via API polling
- Neuro analytics for query analysis
- Responsive design for all screen sizes

### Hermes Agent Dashboard (Port 8082)
- FastAPI-based tool execution
- Shell command execution
- File operations
- System monitoring
- Process management

### Technitium Admin (Port 8080)
- Cached DNS management
- Zone configuration
- Client settings
- Stats and reports

## Domains Configured
- sitet.top (forward zone)
- cafenetmordad.ir (forward zone)
- mordaddns.ir (forward zone)

## Censorship Bypass
- Tor SOCKS5 proxy on port 9050
- DNS queries routed via Tor when needed
- Fallback DNS servers: 9.9.9.9, 1.1.1.1
- DPI evasion capabilities

## Architecture Features
- Zero upstream DNS resolver
- No blocklists or filtering (ZERO-BLOCK policy)
- DNSSEC validation
- DoT (TLS), DoH (HTTPS), DoQ (QUIC) support
- IPv4 and IPv6 dual-stack
- Private DNS support
- All RFC standards supported

## File Locations
- Base Directory: `/opt/souran-ai/`
- Scripts: `/home/reza/souran-kb/scripts/`
- Data: `/opt/souran-ai/data/`
- Logs: `/opt/souran-ai/logs/`
- DNS App: `/opt/souran-ai/dns/`

## Installation
Run the installation script:
```bash
/opt/souran-ai/install-v5.2.0.sh
```

Or use the main control script:
```bash
/opt/souran-ai/souran-ai check
/opt/souran-ai/souran-ai status
/opt/souran-ai/souran-ai restart
```

## Migration
Data migrated from v5.1.0:
- Stats: `/opt/souran-ai/data/stats.json`
- Zones: `/opt/souran-ai/data/zones.json`
- API token: `/etc/dns/api-token.txt`
- Migration log: `/opt/souran-ai/logs/migration.log`