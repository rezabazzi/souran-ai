# Censorship bypass tools — what is installed and what actually works

Audit date: 2026-10-04 (v4.3.0)

## Summary

| Tool | Status | Evidence |
|---|---|---|
| zapret (`nfqws` + `tpws`) | **working** | `souran-zapret.service` active; both binaries bound to nf_queue 151 and :9031 |
| Tor (`tor@default`) | **working** | SOCKS :9050/:9051, DNS :9053; HTTP 301 via SOCKS in ~1.0 s |
| cloudflared | **working** | tunnel registered, protocol=http2 (QUIC is blocked here) |
| privoxy | **working** | :8118, the HTTP proxy the rest of the stack egresses through |
| sing-box / xray / hysteria / shadowsocks | **installed, not enabled as Souran units** | binaries present, no `souran-*.service` |
| webtunnel, dnstt, udp2raw | **installed, not enabled** | binaries present in `/usr/local/bin`, no units |
| GoodbyeDPI | **CANNOT BE INSTALLED — Windows only** | see below |
| ByeDPI / ciadpi | **built from source, INSTALLED, but non-functional on this host** | see below |

## GoodbyeDPI cannot run on Linux

`/opt/souran-ai/censorship/goodbyedpi/src` is a real clone of
ValdikSS/GoodbyeDPI, but that project is **Windows-only by construction**: its
build requires WinDivert (a Windows kernel packet-filter driver) and its
Makefile hardcodes `x86_64-w64-mingw32-gcc`. Building it here fails at:

```
goodbyedpi.c:15:10: fatal error: windivert.h: No such file or directory
```

The upstream README itself lists Linux alternatives and states the project is
built with mingw + WinDivert. The historical `scripts/souran-goodbyedpi.sh`
wrapper papered over this with `exit 0` fallbacks, which is why it looked
installed while producing no binary. Do not use that wrapper as evidence.

## ByeDPI (the Linux port) — built, installed, but cannot parse modern TLS

Installed from source (hufrea/byedpi, GPL-3.0) as `ciadpi` at
`/usr/local/bin/ciadpi`, with `/usr/local/bin/byedpi` symlinked to it. Unit:
`souran-byedpi.service`, listening on 127.0.0.1:1080.

It builds cleanly and starts, but **every proxied request fails immediately**:

```
$ curl --proxy http://127.0.0.1:1080 https://telegram.org
HTTP 000 in 0.000336s

# ciadpi log:
accept: fd=5
alloc new buffer
ss: invalid version: 0x43 (116)
close: fd=5 (pair=-1), recv: 0, rounds: 0
```

`ss:` is ciadpi's TLS ClientHello parser. `0x43` is not a TLS record type
(record types are 0x14 CCS / 0x15 Alert / 0x16 Handshake / 0x17 AppData), so
the parser is rejecting the very first bytes of the ClientHello. This is a
parser that predates TLS 1.3's ClientHello layout. It is **not** a
configuration problem: it fails identically with no desync flags at all, and
with `--tls-max 1.2` forced on the client.

Consequence: do not point any client at :1080 expecting a bypass. It is left
running so the capability is present and inspectable, but the honest status is
**non-functional on this host**. The working DPI bypass on this machine is
**zapret** (`nfqws`/`tpws`), which operates at the netfilter queue and does
not need to parse TLS at all.

## What actually provides censorship resistance here

1. **zapret** (`souran-zapret.service`) — real DPI desync at nfnetlink queue 151
   (`nfqws --dpi-desync=fake --hostlist=...`) plus `tpws` on :9031. This is the
   active bypass.
2. **DoH over 443 to pinned bootstrap IPs** in `souran-doh-fallback.py` — the
   resolver's Tier 2. Python's TLS ClientHello is DPI-reset here, so it shells
   out to `curl` and pins IPs with `--resolve`, keeping SNI + cert validation.
3. **Tor + privoxy** — general egress, used by the learning engine and fwupd.
4. **Untrusted-UDP/QUIC demotion** via `quic`/`disable_udp` host handling in
   the zapret hostlist.

## Enabling the dormant transports

`webtunnel-server/client`, `dnstt-server`, `udp2raw`, `sing-box`, `xray` and
`hysteria` are built and present but have no `souran-*.service`, so nothing
starts them at boot. They are intentionally left off: each needs a working
remote peer (a VPS or bridge) and a transport/port plan. Turning them on
without peers would produce units that start, fail, and retry forever — which
is worse than an honest "installed, not configured".

See `censorship/README.md` for the peer/port requirements before enabling any
of them.