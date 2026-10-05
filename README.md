# Souran AI Network Server

A censorship-resistant, self-hosted recursive DNS resolver and circumvention
stack for Linux. Built from source. No upstream forwarders, no black-box
binaries, no third-party resolver in the path.

**Version 5.1.0** · GPL-3.0-or-later · Python 3.12+ · unbound 1.26.2

---

## What problem this actually solves

On a censored network, DNS is the first thing an attacker controls. Plain
UDP/53 responses are trivially forged: on the network this was developed
on, `telegram.org` reliably resolved to `10.10.34.36` — a private,
unroutable address — while the real answer is `149.154.167.99`. A client
that trusts the answer never reaches Telegram. It reaches whatever the
injector chose.

Most "private DNS" products solve this by *hiding* resolution behind
Google or Cloudflare. That works until the resolver itself is blocked,
and it hands your complete DNS history to a company you did not choose.

This does three things instead:

1. **Resolves from the root hints downward, itself.** unbound starts at the
   root and follows delegations. There is no forwarder to poison,
   because there is no forwarder.

2. **Forces TCP for upstream queries.** UDP/53 is spoofable in flight;
   TCP is not. This costs some latency on a lossy link and buys
   authenticity. It is the single most important line in the config.

3. **Cross-checks every answer, and escalates.** A public name resolving
   to an RFC1918, loopback or link-local address is this network's
   injection signature. Such answers are rejected, never cached, and the
   query is escalated to DNS-over-HTTPS on port 443 — the one transport
   that is clean here.

The result: correct answers for censored and uncensored domains alike,
with no reliance on anyone else's resolver.

---

## Architecture

```
        client
          |
          v
    +---------------+   plain DNS     the public entry point
    |  :53  :853    |   DoT
    |  :8083        |   DoH
    +-------+-------+
            |
            v
    +-------------------+
    | poison-proof      |  rejects injected answers,
    | front-end (Python)|  escalates to DoH over 443
    +--------+----------+
             | tier 1: zero-upstream
             v
    +-------------------+
    | unbound  :5399    |  root-anchored, TCP upstream,
    | (from source)     |  DNSSEC, aggressive cache
    +-------------------+
```

Encrypted-DNS transports are terminated by the same front-end, so DoT and
DoH get the identical poison-checking guarantee as port 53 — not a weaker
copy of it.

---

## Features

Every capability is independently switchable, with **31 registered
features** across five categories:

| Category | Count | Examples |
|---|---|---|
| `dns` | 9 | zero-upstream recursion, DoT, DoH, cache/prefetch, DNSSEC, forced-TCP upstream, DoH escalation |
| `censorship` | 10 | zapret DPI desync, ciadpi, Tor, SOCKS bridge, outbound-DNS-via-Tor, Xray, Hysteria2, sing-box, plus two optional (Ouinet, Veltor) |
| `ops` | 9 | watchdog, intrusion detection, Cloudflare tunnel, host firewall, learning engine, anti-compression, both dashboards, control API |
| `web3` | 2 | ENS / blockchain name resolution, RPC gateway |
| `gaming` | 1 | game-service resolver profile |

### Desired state is not effective state

The registry reports two things separately, and this is deliberate:

- **desired** — what you asked for
- **effective** — what a live probe says is actually true

A toggle can read "on" while the service is stopped. That is exactly the
kind of lie the registry exists to eliminate, so both dashboards show the
probed state and flag the difference as **drift** rather than hiding it.

```console
$ curl -s localhost:9192/api/features/summary/categories | jq .summary
{ "total": 31, "on": 28, "off": 3, "drifted": 0 }
```

---

## Install

### From the .deb

```bash
sudo dpkg -i souran_5.1.0_amd64.deb
```

A **fresh** install starts nothing and says so: it claims port 53, so
activating it is an explicit decision.

```bash
sudo /opt/souran-ai/souran-enable-all
```

An **upgrade** is invisible — the package records which units were running
and restores them, then reconciles the rest against the registry's desired
state. Recovering from a fully-stopped machine is part of the tested
behaviour, not a happy accident.

### From source

```bash
git clone <repo> souran-ai && cd souran-ai
sudo ./install-souran.sh
```

### What the postinst does

- creates the `unbound` service account if absent
- **issues a fresh TLS CA and leaf certificate** (see below)
- grants only `CAP_NET_BIND_SERVICE` to the resolver — it is never root
- creates the control-plane API token at `/etc/souran/api-token`, mode
  0600, outside the source tree
- restores previously-running units, then reconciles the rest

---

## Encrypted DNS, and why it needed a real PKI

The first working version of DoT was unusable by any real client. The
certificate was a bare self-signed leaf with **no subjectAltName**:

```
subject=CN=souran.local, O=Souran AI, C=IR
No extensions in certificate
```

Android Private DNS, Windows DNS-over-HTTPS and macOS all validate the
hostname against the SAN list. The feature this project exists to provide
could not be switched on by a phone or a PC.

`souran-certgen.sh` now builds a proper two-level PKI:

```bash
sudo ./souran-certgen.sh issue            # root CA + leaf with SANs
sudo ./souran-certgen.sh export-client ~/souran-ca
```

The leaf carries DNS and IP SANs for every name a client might use. IP
literals go in IP SAN — putting them in DNS SAN is silently ignored.

Export the root CA to a client once, and that client trusts this
resolver. That is the correct model: DoT exists to authenticate the
channel to *your* resolver, not to a public CA.

---

## Client (Windows / macOS / Linux / Android)

One file, standard library only, no build step.

```bash
# always test before applying — never point a machine at a dead server
python3 souran_client.py test --server mordaddns.ir --ca souran-dns-ca.crt

# dry run: prints what it would change
python3 souran_client.py apply --server mordaddns.ir --ca souran-dns-ca.crt

# apply for real
python3 souran_client.py apply --server mordaddns.ir --ca souran-dns-ca.crt --yes
```

| Platform | Mechanism | Needs root |
|---|---|---|
| Linux | `resolvectl dns` / `systemd-resolved`; falls back to `/etc/resolv.conf` with a backup | yes |
| macOS | `networksetup -setdnsservers` per active service | yes |
| Windows | `netsh interface ip set dnsservers` + `validate=no` for DoH | yes (elevated) |
| Android | **not automated** — see below | n/a |

Android gets printed instructions instead of automation, on purpose:
Private DNS is a user-facing Settings toggle, it always uses DoT on 853
with no port field, and automating it would require root or an
accessibility service.

```bash
python3 souran_client.py android --server mordaddns.ir --ca souran-dns-ca.crt
```

Three properties this client will not compromise:

1. **Certificate trust is never silently disabled.** If the CA is not
   installed, the answer is that DoT does not work yet.
2. **No subprocess shell strings.** Every external command is an argv
   list with `shell=False`, and hostnames are validated first.
3. **Dry run by default**, and `apply` refuses to act unless `test` passes.

---

## Security

| Control | Detail |
|---|---|
| Control-plane auth | 0600 token, constant-time compare, loopback-exempt so the watchdog and tests keep working |
| Host firewall | nftables, INPUT default-deny; OUTPUT deliberately unfiltered |
| TLS | local root CA + SAN-bearing leaf; keys root-owned, group-readable only by the two services that need them |
| Poison detection | IPv4 **and** IPv6, including this network's string-appended AAAA forgery |
| Resolver version | unbound 1.26.2 — patched for CVE-2026-85501, with the advisory's limits set explicitly |
| Secrets | never in the source tree, never in the package, never in git |

### CVE-2026-85501 ("ReTrap")

The resolver previously ran unbound 1.24.2, which is affected by a
published algorithmic-complexity DoS: *"Unbound up to and including
1.26.0 is vulnerable."* One malicious zone can drive the resolver into
unbounded work through TagTrap, DelegationTrap, NsecTrap or
AdditionalTrap — a directly triggerable availability attack against a
resolver whose entire purpose is availability on a hostile network.

Fixed by building 1.26.2 from source and **replacing the vendored source
too**, since the package compiles from `engine/unbound-src` and a rebuild
would otherwise have shipped the vulnerable version again while looking
successful. `build-deb-payload.sh` now refuses to package any resolver
binary that is not 1.26.2.

### Two judgement calls worth stating

**OUTPUT is not filtered.** The machine exists to reach DNS authorities
and DoH resolvers across a censored network, through Tor and DPI-desync
transports. An egress policy would break censorship bypass by
construction. The risk accepted is a compromised local process reaching
the network — materially smaller than the resolver refusing to resolve
anything.

**The NAT table is never flushed.** It holds the outbound DNS→Tor
redirect and the cloudflared 7844→17844 redirect. `nft flush ruleset`
would silently destroy the entire bypass stack, which is why reloading
deletes only this package's own table.

---

## Testing

Every fix in the changelog has a regression test that fails without it.

```bash
python3 tests/test_auth.py          # 15 — control-plane auth
python3 tests/test_poison.py        # 34 — IPv4 + IPv6 poison detection
python3 tests/test_rcode.py         # 10 — NXDOMAIN/NODATA fidelity
python3 tests/test_dot.py           #  9 — DoT, chain, hostname validation
sudo python3 tests/test_firewall.py # 15 — real off-host packet filtering
```

The firewall test builds a network namespace with a veth peer so packets
genuinely traverse the INPUT chain. Connecting to the host's own LAN
address does not — that traffic goes out via OUTPUT — which is why an
earlier version of that test appeared to prove the rules were not
filtering when they were working correctly.

---

## Building the package

```bash
./build-deb-payload.sh debian/tmp
sudo dpkg-buildpackage -b -us -uc
lintian ../souran_5.1.0_amd64.deb      # 0 errors
```

`build-deb-payload.sh` refuses to produce a payload containing a private
key, a queued feature intent, or a resolver binary other than 1.26.2.
Each is a hard `exit 1`, not a warning: the root CA key is the trust
anchor for every client, and leaking it would let anyone mint a
certificate for this resolver's name.

---

## Repository layout

```
souran_features.py          feature registry: state, probes, drift detection
souran_auth.py              token generation, storage, constant-time compare
souran-doh-fallback.py      poison-proof front-end owning :53, :853, health :54
souran_dns_rr.py            DNS wire format, rcode-correct response builders
souran_portmap.py           live inventory of every port, with purpose
souran_technitium.py        Technitium DNS Server API client (allowlisted)
souran_dashboard.py         control dashboard (:8082)
web-dashboard-8383.py       telemetry dashboard (:8383), registry passthrough
souran_client.py            cross-platform client configurator
souran-certgen.sh           TLS CA + leaf issuance
souran-firewall.sh          nftables control
souran-feature-apply.sh     privileged actuator (allowlisted actions only)
souran-feature-executor.sh  root executor for the intent queue
config/souran-firewall.nft  the ruleset
engine/unbound-src/         unbound 1.26.2, compiled during the build
debian/                     package metadata and maintainer scripts
tests/                      regression suites
```

### Why the privileged split

The control-plane services run with `NoNewPrivileges=yes`. That is
correct hardening and it is not negotiable — it is what stops a
compromised request handler from escalating. It also makes the setuid bit
inert, so `sudo` is impossible from inside them.

Two mutation designs were tried and both failed for that reason. The
resolution is to split privilege from control: the unprivileged process
writes an **intent**, and a root executor on a 15-second timer applies
it. The hardening is unchanged, and every action is logged.

---

## Known limitations

Stated plainly rather than left to be discovered:

- **DNSSEC validation is off by default.** Tor's exits strip RRSIG
  records, so strict validation cannot complete over the Tor transport and
  fails closed. It is a per-feature toggle for a direct, un-tunnelled
  path. With it off, the defences that remain are forced-TCP upstream, the
  DoH tier, and the private-address filter.
- **DoQ and DoH3 are unavailable.** unbound 1.26.2 here is built without
  `ngtcp2`, so `quic-port:` cannot work. sing-box can serve both, which
  is why it is registered as a feature.
- **The operator's public domains had no A records**, so clients cannot
  reach the resolver by hostname yet. `souran_client.py --connect-ip`
  exists for exactly this case and still validates the certificate for
  the named server.
- **A banned domain resolving is not a bug.** On this network a timeout
  or NXDOMAIN for a censored domain is the correct answer.

---

## Credits

- **unbound** — NLnet Labs, BSD-3-Clause. Recursive resolver, built from
  source.
- **Technitium DNS Server** — Shreyas Zare. API client built against the
  vendor's published specification.
- **zapret**, **ciadpi** — DPI desync implementations.
- **Tor**, **privoxy**, **cloudflared**, **Xray**, **Hysteria2**,
  **sing-box** — circumvention transports.

## License

GPL-3.0-or-later. See `LICENSE` and `debian/copyright`.