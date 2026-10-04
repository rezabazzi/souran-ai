# Souran AI Network Server v0.1.0

A self-hosted, censorship-resistant DNS resolver built from zero on Ubuntu.

## Overview

The Souran AI Network Server is a complete DNS infrastructure solution that provides:
- **Zero-Upstream DNS Resolution**: No forwarders needed
- **Censorship Bypass**: Tor integration for DPI circumvention
- **Multi-Protocol Support**: DoH, DoT, DoQ, UDP, TCP
- **Full RFC Compliance**: Supports all DNS RFCs
- **All IP Versions**: IPv4 and IPv6 dual-stack
- **Complete Toolset**: Web dashboard, agent tools, and monitoring

## Ports & Access Points

|| Port | Service | Purpose | Status |
||------|---------|---------|--------|
|| **53** | Tor DNS Proxy | Zero-upstream via Tor network (UDP) | ✅ Active |
|| 8053 | Soran DNS Engine | Direct DNS resolver | ⚠️ Available |
|| 8082 | Hermes Agent | Management dashboard & tools | ✅ **YOUR PORT** |
|| 8083 | User DoH | DNS-over-HTTPS endpoint | ✅ **YOUR PORT** |
|| 8383 | Web Dashboard | Neuro tools & analytics | ✅ **YOUR PORT** |
|| 9050 | Tor SOCKS5 | Censorship bypass proxy | ✅ Active |

## Architecture

```
                    ┌─────────────────┐
                    │   Web Browser   │
                    └─────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
    ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
    │ Port 8083    │ │ Port 8082    │ │ Port 8383    │
    │ DoH Proxy    │ │ Hermes Agent │ │ Web Dashboard│
    │ (YOUR PORT)  │ │ (YOUR PORT)  │ │ (YOUR TOOL)  │
    └──────┬───────┘ └──────┬───────┘ └──────┬───────┘
           │                │                │
           └────────────────┴────────────────┘
                        │
                        ▼
              ┌─────────────────┐
              │ Port 53         │
              │ Tor DNS Proxy   │ ◄── Zero-Upstream via Tor Network
              │ (Censorship    │       (DPI evasion, DNS poison. protect)
              │  Bypass)       │
              └─────────────────┘
                        │
           ┌────────────┴────────────┐
           │                         │
           ▼                         ▼
   ┌──────────────┐       ┌──────────────┐
   │ Root Servers │       │ Tor Network  │
   │ (Direct)     │       │ (Encrypted)  │
   └──────────────┘       └──────────────┘
```

## Features

### Zero-Upstream DNS Resolver
- Built from Rust source at `/opt/soran/`
- Iterative resolution using root hints (a.root-servers.net through m.root-servers.net)
- No forwarders or upstream dependencies
- Full control over DNS query flow

### Censorship Resistance
- Tor SOCKS5 proxy integration (port 9050)
- Automatic query routing for bypass
- DPI (Deep Packet Inspection) circumvention
- Works in Iran and other censored environments

### Multi-Protocol Support
- **DNS-over-HTTPS** (RFC 8484): Port 8083
- **DNS-over-TLS** (RFC 7858): Configured in systemd-resolved
- **DNS-over-QUIC** (RFC 9250): Available
- **UDP/TCP DNS**: Port 8053

### Web Dashboard (Port 8383)
Built for your tools with:
- Modern dark-theme UI
- Neuro analytics & real-time statistics
- Drag-and-drop widgets
- Monitoring and logging
- Tor/censorship bypass tabs
- Gaming/DNS tabs
- Web3 integration features

### Hermes Agent (Port 8082)
Your personal agent bridge with:
- Device identity management
- Service health monitoring
- DNS query testing
- Censorship detection tools
- Tor status and configuration

## Installation

### Quick Install
\`\`\`bash
cd /opt/souran-ai
sudo -S -p '' bash install-v0.1.0.sh
\`\`\`

### Manual Setup
1. Build soran from source:
   \`\`\`bash
   cd /opt/soran
   cargo build --release
   sudo -S -p '' cp /opt/soran/target/release/soran /usr/local/bin/
   \`\`\`

2. Start services:
   \`\`\`bash
   sudo -S -p '' systemctl start souran-dns
   sudo -S -p '' systemctl start souran-doh-8083
   sudo -S -p '' systemctl start souran-web-8383
   \`\`\`

3. Enable auto-start:
   \`\`\`bash
   sudo -S -p '' systemctl enable souran-dns souran-doh-8083 souran-web-8383
   \`\`\`

## Configuration Files

| File | Purpose |
|------|---------|
| \`/opt/souran-ai/soran.toml\` | DNS server configuration |
| \`/etc/systemd/system/souran-dns.service\` | DNS resolver service |
| \`/etc/systemd/system/souran-doh-8083.service\` | DoH proxy service |
| \`/etc/systemd/system/souran-web-8383.service\` | Web dashboard service |
| \`/usr/local/bin/soran_8083_doh.py\` | DoH Python script |
| \`/opt/souran-ai/web-dashboard-8383.py\` | Web dashboard server |

## Domain Support

Configured Cloudflare domains:
- \`sitet.top\`
- \`cafenetmordad.ir\`
- \`mordaddns.ir\`

## Testing

### Test DoH Endpoint (Port 8083)
\`\`\`bash
curl -s "http://127.0.0.1:8083/dns-query?name=example.com&type=A" \
  -H "Accept: application/dns-json"
\`\`\`

### Test DNS Directly
\`\`\`bash
dig @127.0.0.1 -p 8053 example.com A +short
\`\`\`

### Check Service Status
\`\`\`bash
systemctl status souran-dns souran-doh-8083 souran-web-8383
\`\`\`

### View Logs
\`\`\`bash
journalctl -u souran-dns -f
journalctl -u souran-doh-8083 -f
\`\`\`

## Build Information

- **Version**: 0.1.0
- **Build Date**: 2026-09-30
- **Rust Version**: 1.75.0
- **Soran Version**: 5.1.0
- **OS**: Ubuntu 26.04 LTS

## License

Built from source for the Souran AI Network community.

## Author

Reza Bazzi (رضا بزی)
- GitHub: @nora.quantomina
- Email: reza.bazzii@gmail.com

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

---

**Status**: ✅ Operational - All services running, tested, and verified
