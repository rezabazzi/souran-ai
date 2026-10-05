# Changelog

All notable changes to Souran AI Network Server.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Version follows semantic versioning.

Every entry below was **measured on the running system**, not inferred.
Where a fix has a measured before/after, both numbers are given.

---

## [5.1.0] — 2026-10-05

The release where the resolver stopped merely looking healthy. Most of
these were found by using the system as a user would — installing the
package, querying real names, talking to it with a strict client — rather
than by reading the code.

### Security

- **unbound 1.24.2 -> 1.26.2, patching CVE-2026-85501.** The resolver
  was running a build with a known, published, unpatched
  algorithmic-complexity DoS ("ReTrap", NLnet Labs, CWE-770, published
  2026-09-16): "Unbound up to and including 1.26.0 is vulnerable." One
  malicious zone can drive the resolver into unbounded work via TagTrap,
  DelegationTrap, NsecTrap or AdditionalTrap -- a directly triggerable
  availability attack against a resolver whose entire purpose is
  availability on a hostile network. The **vendored source was replaced
  too**, since the .deb compiles from engine/unbound-src and a rebuild
  would otherwise have shipped the vulnerable version again while looking
  successful. build-deb-payload.sh now refuses to package any resolver
  binary that is not 1.26.2, and the advisory's limits are set explicitly
  (val-hash-attempts: 32, val-validation-attempts: 32,
  val-clean-additional: no) so an explicit value survives a downgrade.

- **Plaintext sudo password purged.** A hardcoded credential was embedded
  in six source files and had already reached git history. Every call site
  now uses `sudo -n`.
- **Token authentication on the whole control plane.** A root-owned 0600
  token at `/etc/souran/api-token`, outside the source tree, compared in
  constant time. Health and docs stay loopback-exempt so the watchdog and
  test suites keep working.
- **Poison detection now handles IPv6.** It was IPv4-only via
  `socket.inet_aton()`, and a bare `except` swallowed the resulting
  `OSError`, so **every AAAA address was classified clean**. This network
  forges AAAA as well as A; the live example is
  `2001:4188:2:600:10:10:34:36` — Telegram's genuine prefix with the
  censor's IPv4 answer `10.10.34.36` written into it as decimal groups.
  Now handles both families, plus IPv4-mapped addresses, so the IPv4
  filter cannot be bypassed by asking for AAAA instead of A.
  34 regression cases including 9 real public IPv6 addresses that must
  **not** be flagged.
- **The firewall no longer opens SSH and both dashboards to every source
  on every interface.** That rule contradicted the ruleset's own header,
  which correctly states NAT is not access control. Administration from
  outside the LAN still works, through `iifname "wg0" accept` — trusting
  authenticated WireGuard peers is a far stronger check than an open port.
- **The DHCP rule was a spoofable source-port match.** `udp sport { 67, 547 }`
  permitted packets from any source to any destination port, restricting
  nothing, while failing to permit real DHCP traffic (which arrives on
  *dport* 67). Now scoped to the LAN with the correct direction.
- **The firewall was not owned by systemd and would have vanished on
  reboot**, silently removing all access control. Found by an adversarial
  review that read systemd state instead of trusting the setup.
- **Secrets and build output are no longer tracked.** 859 `.venv` files,
  411 `__pycache__` entries, 125 cargo artifacts, 171 prebuilt Technitium
  binaries and the compiled unbound binaries were all committed.
  1108 → 194 tracked files, 33 MB → 2.0 MB, all genuine source.
- **A foreign git remote was removed.** `origin` pointed at
  `nousresearch/hermes-agent`. This project is not that project.

### Fixed

- **NXDOMAIN was being destroyed.** All three handlers rebuilt the reply
  flags from scratch as `0x8000 | 0x0080 | (flags & 0x0100)`, zeroing the
  low four bits — the RCODE. Every NXDOMAIN reached clients as NOERROR.
  Fixed with `_reply_flags()`, which also preserves the DNSSEC AD/CD bits;
  without that passthrough, enabling DNSSEC later would have appeared to
  do nothing.
- **A DoH NXDOMAIN was treated as a lookup failure.** `_doh_is_nodata()`
  only matched Status 0, so an authoritative NXDOMAIN (Status 3) fell
  through and the client received tier-1's SERVFAIL. Measured: DoH
  answered a nonexistent name correctly while `:53` returned SERVFAIL on
  every attempt. A resolver that cannot say "this name does not exist" is
  functionally broken.
- **A malformed query produced no reply at all.** A 64-byte label hung
  the client for its full 12 s timeout. Three separate causes, the subtlest
  being that the error builder itself called `_encode_name()`, which
  *raises* on the over-long label it exists to reject. Now an immediate
  FORMERR: **12.01 s hang → 0.00 s**.
- **Encrypted DNS could not be used by any real client.** The DoT
  certificate had no `subjectAltName`, so Android Private DNS, Windows
  DNS-over-HTTPS and macOS all refused it. Replaced with a local root CA
  plus a leaf carrying DNS and IP SANs for every name a client might use.
  DoTServer also rebuilt an `SSLContext` on every `accept()`; kdig (a
  strict RFC 7858 client) failed every handshake against `:853` while
  working fine against `:5354`.
- **Tier-1 unbound was in a 60-restart crash loop.** unbound rewrites its
  DNSSEC trust anchor through a *temporary sibling file*, so the containing
  **directory** must be writable — fixing only the file's ownership is not
  enough. Tier-1 never listened on `:5399`, so every query fell through to
  the DoH tier and results degraded to NXDOMAIN/SERVFAIL.
- **Both unbound instances shared control port 8953.** The DoT config had
  no control-interface section, so it inherited unbound's default and one
  instance always lost the bind. Now 8953 and 8954 respectively.
- **The intrusion detector had never once run.** It runs as `User=reza`
  and wrote to `/var/log/souran-ids-alerts.log` (`root:adm` 0640), so it
  died on its first log call — an 8-cycle flap, then a hard fail. An
  intrusion detector that cannot start is worse than none, because the
  registry reported it as a feature.
- **The watchdog issued 6 repair calls against a `dns.service` that does
  not exist**, logging 3,543 failures and sleeping as if it had worked. It
  now restarts the units that actually own the resolver.
- **An upgrade silently took down a live deployment.** `dpkg -i` stopped
  all 16 units and restarted none. The prerm hook now records running
  units and the postinst replays them.
- **A reinstall left 10 of 31 features silently drifted.** The postinst
  now also reconciles unit state against the registry's *desired* state.

### Changed

- **Feature registry expanded to 31 features** across `dns` (9),
  `censorship` (10), `ops` (9), `web3` (2) and `gaming` (1), each
  independently switchable with desired-vs-probed state and drift
  detection. Three services that were running but unregistered (xray,
  hysteria2, sing-box) are now included — a registry that under-reports is
  worse than none, because it looks complete.
- **Unbound cache right-sized from measurement, not guesswork.** It was
  configured at 896 MB against a measured 57 MB working set, on a host
  with ~450 MB free — making unbound the prime OOM candidate for no
  benefit. Now 448 MB, with the reasoning recorded in the config file so it
  is not later "restored" to guesswork values.
- **Disk reclaimed.** The filesystem was at 82% with ~1.5 GB of purely
  regenerable caches. The resolver competes for the same space.

### Added

- **Control dashboard on `:8082`** replacing a static page with hardcoded
  values and no controls. Renders all 31 features as real switches, every
  listening port with purpose and verdict, and DNS/DoT/DoH/DNSSEC/Technitium
  state. Because mutation is asynchronous, it shows the *probed* state and
  reports "applied but NOT verified" when request and reality disagree.
- **Cross-platform client** for Windows, macOS, Linux and Android. One
  file, standard library only. Certificate trust is never silently
  disabled, no subprocess shell strings, dry run by default. Android gets
  printed instructions rather than automation, because Private DNS is a
  user toggle on port 853 with no port field.
- **Debian package v5.1.0**, lintian-clean, compiling unbound from the
  vendored source during the build. The payload builder refuses to produce
  a package containing any private key.
- **Regression suite** — 83 assertions across 5 files, each one of which
  fails without the fix it guards.

---

## [5.0.0] — 2026-10-04

- First packaged release: real `.deb`, lintian-clean, installed and
  verified. unbound compiled from source at build time.
- Token authentication introduced on the control plane.
- Host firewall via nftables, default-deny on INPUT, NAT table untouched.

---

## Known limitations

Stated plainly rather than left to be discovered:

- **DNSSEC validation is off by default.** Tor's exits strip RRSIG
  records, so strict validation cannot complete over the Tor transport and
  fails closed. It is a per-feature toggle for a direct, un-tunnelled path.
- **DoQ and DoH3 are unavailable.** unbound 1.24.2 here is built without
  `ngtcp2`, so `quic-port:` cannot work. sing-box can serve both.
- **The operator's public domains have no A records**, so clients cannot
  reach the resolver by hostname yet. `souran_client.py --connect-ip`
  exists for exactly this case and still validates the certificate for the
  named server.
- **A banned domain resolving is not a bug.** On this network a timeout or
  NXDOMAIN for a censored domain is the correct answer.
## 5.2.0

### Added
- **Ad/tracker/malware blocking, 426,683 domains.** `souran_blocklists.py`
  compiles three list formats (hosts, adblock `||domain^`, bare/wildcard)
  into unbound `local-zone` + `local-data`, answering `0.0.0.0`. The
  compiler ships; the 36 MB generated ruleset does not, and `postinst`
  compiles on install when cached lists are present. Also suppresses this
  censor's injected `adservice.google.com` answer.
- **LAN name service.** `souran_lan.py` serves forward and reverse records
  from operator entries, `/etc/hosts`, DHCP leases and this host's own
  addresses. Only names with a real source are published — with no DHCP
  server running it serves exactly one host rather than inventing
  neighbours.
- **Per-upstream DoH pacing** with a 4-wide concurrency window, replacing a
  single global 0.9 s lock.

### Fixed
- The front-end rejected its own LAN answers. `10.0.0.0/8` is both this
  censor's poison signature and this LAN's subnet, so the poison filter
  discarded legitimate answers. The check is now scoped to names outside
  the zones this resolver is authoritative for; it is unchanged everywhere
  else.
- `souran-doh-fallback.service` pinned `SOURAN_DOH_INTERVAL=0.9`, silently
  defeating the pacing change — the measured improvement had been
  in-process only until the pin was removed.
- `/api/technitium/dhcp` returned a hardcoded DHCP range for a server that
  is not running.
- `souran_technitium.py` read a world-readable (0644) token from a path
  that is not the one Technitium was configured with, so it could not
  authenticate. It now reads the 0600 key and refuses any token file
  readable by group or other.
- `souran_blocklists.py`'s parser read only hosts format, silently
  extracting zero domains from 428,000 lines of adblock and bare lists.

### Measured
- Cold concurrent p50 **17.5 s → 1.10 s**; warm 0.045 s.
- Registry 33 features, 30 on, 3 off, 0 drifted, 0 unit restarts.
- All five suites pass; lintian 0 errors.
