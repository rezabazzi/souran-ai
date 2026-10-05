# Roadmap

Verified against the live system and real upstream sources on **2026-10-05**.
Every item below was checked; items that had already been addressed by v5.1.0
are marked as such rather than silently dropped.

Notation: **[DONE]** shipped in 5.1.0 · **[P0/P1/P2]** priority

---

## Verified network constraints (the reason most of this list exists)

Measured from this host, not assumed:

| Transport | State | Consequence |
|---|---|---|
| TCP/443 | OPEN | DoH works; this is the escalation tier |
| **UDP/443** | **OPEN** | **QUIC/DoH3 and DoQ are the only encrypted DNS that survives** |
| TCP/853 | **BLOCKED** | DoT is useless for remote clients on this link |
| UDP/53 | open but forged | plain DNS cannot be trusted |

The UDP/443 result is what makes the P1 QUIC work the highest-value item:
QUIC-over-443 is indistinguishable from web traffic by port, and it is the
one encrypted DNS transport that does not require TCP/853 or trust in
UDP/53.

---

## [DONE] — shipped in v5.1.0

- **unbound 1.24.2 → 1.26.2.** Not a nicety: 1.26.1 bundled eight CVEs
  including CVE-2026-85501 (ReTrap DNSSEC algorithmic-complexity DoS),
  and 1.25.0 fixed a **DNS-rebinding bypass via SVCB/HTTPS records** —
  directly load-bearing, because the front-end is the tier enforcing the
  private-address filter.
- **IPv4 + IPv6 poison detection.** The old filter was IPv4-only and
  classified *every* AAAA address as clean.
- **Xray / Hysteria2 / sing-box registered** as switchable features — they
  were running but unlisted, so the registry was under-reporting.
- **Correct rcode fidelity** — NXDOMAIN was reaching clients as NOERROR.

---

## [P0] — highest value, lowest effort

### 1. Rebuild unbound with `ngtcp2` to unlock DoQ (RFC 9250) and DoH3

**Why here:** the measured table above. DoT (853) is blocked and UDP/53 is
forged, so the QUIC transports are the interesting candidates. This build
has **no ngtcp2** (`ldd` confirms), so `quic-port:` cannot work at all.

**Approach**
1. Build `ngtcp2` + `nghttp3` from source.
2. Rebuild unbound with `--with-libngtcp2 --with-libnghttp3`.
3. Add a third escalation tier: **DoH3 → DoH/443 → DoQ → local unbound**,
   each with its own health probe.
4. Register `dns_doq` and `dns_doh3` in the feature registry.

**Difficulty:** medium.

#### What I could NOT verify, and one correction

The research report claimed DoH3 was "achievable today with no rebuild"
via sing-box's `type: "h3"`. **That is wrong for this build, and I checked
rather than assumed:**

- sing-box's config schema does accept a `dns` server of `type: "h3"`, and
  it passed `sing-box check`.
- But sing-box 1.14's `dns` block is **client-side only** — it resolves
  names for sing-box's own routing. Enumerating the schema's `Inbound`
  union gives 19 inbound types and `dns` is **not among them**. So it
  cannot expose DoH3 to our front-end. A `mixed` inbound on 5353 answers
  HTTP 400, not DNS — confirmed by hand.
- This host's curl has **no HTTP/3 support** (`libcurl/8.18.0` built
  without ngtcp2/nghttp3), so the front-end cannot use a QUIC DoH client
  either.

**DoH3/DoQ therefore require the ngtcp2 rebuild above. There is no
no-rebuild shortcut on this host.**

**QUIC reachability is UNKNOWN, not verified.** A probe sending a
hand-built QUIC Initial to 1.1.1.1 / 8.8.8.8 / 9.9.9.9 on UDP/443 got no
reply in 6s from all three — but that proves nothing, because conformant
servers silently ignore an invalid Initial. A real test needs a working
QUIC client, i.e. the rebuild itself. **Build it and measure before
committing any design to QUIC.**

### 2. Statistical poisoning detection — the filter has a real blind spot

**The gap, measured:** `is_poison()` returns `False` for every *public*
address, correctly for real answers like `185.188.104.10` — and equally
correctly for an attacker-hosted poison. Right now the only poison this
resolver can catch is an RFC1918/loopback one, because that is all the
signature-based approach can recognise. A censor that redirects to its own
public address is invisible.

**Approach:** per the TC-flag latch design in POPS (arXiv:2501.13540) —
maintain a rolling answer-distribution per qname; on anomaly (same name
returning an unexpected address set, answer/TTL disagreeing with the DoH
tier, or an answer set flipping between calls), latch the DNS **TC** flag
for that name for a short period and escalate to DoH. POPS reports zero
false positives on detection with a 0.0076% adversary success rate.

The cheap first step needs no research: **when tier-1 and the DoH tier
disagree about the address set for the same name, treat tier-1 as poisoned
and serve DoH.** That reuses the tier we already have.

**Difficulty:** medium.

### 3. Adopt zapret2 (`nfqws2`) as the bypass core

**Verified real:** `bol-van/zapret2` latest is **v1.0.5.2 (2026-09-15)**,
with release tarballs published. zapret v72.3 states zapret1 is likely its
final release; development has moved to zapret2.

**Why it matters here:** the current profile is a hardcoded
`split2,fake` on four ports with a 14-domain hostlist. It works only for
what it was tuned for. `nfqws2` adds:

- **multi-packet QUIC CRYPTO re-assembly** — modern Chrome splits the
  ClientHello across packets, and a naive desync silently fails on it;
- `--filter-mark` so zapret cooperates with the existing nftables rules
  instead of fighting them;
- Lua-scripted desync decisions;
- `--filter-l7=discord,stun` and QUIC/Discord media ports.

**Approach:** build `nfqws2` alongside the existing binary, add
`censor_zapret2` with the same probe contract, add a `zapret-presets/`
directory (QUIC-initial-any-port, discord/stun, wireguard) as overlays.

**Difficulty:** medium. No config semantics change.

### 4. Desync refinements for the *existing* zapret1 binary — cheapest wins

Already present in the installed version, so this is configuration only:

- `ts` (timestamp) fooling, which makes the censor's OS drop the packet
  rather than reassemble it — the standard answer when the DPI is
  statistical rather than SNI-signature based, which is the Iran profile;
- `--dpi-desync=hostfakesplit`;
- `--dpi-desync-tcp-flags-set/unset`, `--ip-id` / `--dup-ip-id`;
- `--dpi-desync-fake-tls-mod=sni=...` for per-domain fake SNIs;
- `--dup-autottl` / `--orig-autottl` with ipcache.

**Difficulty:** low.

---

## [P1] — valuable, medium effort

### 5. Designated Resolver Discovery (RFC 9462) + SVCB/HTTPS hints

Serve `_dns.resolver.arpa` SVCB records advertising this resolver's DoH
and DoT endpoints, so LAN clients can discover the encrypted resolver from
the address alone and move off ISP DNS — which is poisoned here. Pair with
`ech=` params so the DoH endpoint's own SNI can be hidden.

Implemented as a local zone in unbound plus an authoritative zone.

**Difficulty:** low-medium. Clients are the limiting factor.

### 6. IPv6 as an evasion path — currently entirely unused

`do-ip6: no`, and no global IPv6 route. Two 2025 measurement papers
(arXiv:2508.07194 ProtoScan, arXiv:2508.07197 "Mind the IP Gap") report
that censors *do* block IPv6 but **less effectively and less
consistently than their IPv4 infrastructure** — framed explicitly as an
opportunity for circumvention.

Two separable halves:

- **Measurement (do now, no new connectivity needed):** a watchdog probe
  that resolves a canary set over IPv6 and IPv4 and reports divergence, so
  the stack *detects* when censorship differs between them. Valuable even
  while IPv6 egress is unavailable, because it tells you when to care.
- **Egress (needs real IPv6):** `do-ip6: yes` plus DNS64
  (`dns64-prefix: 64:ff9b::/96`, supported natively) so IPv6-only
  destinations stay reachable.

**Difficulty:** measurement low, egress medium.

### 7. Blocking and rate limiting via unbound's native RPZ

There is currently **no blocklist feature at all**, and the registry does
not pretend otherwise. unbound supports `rpz:` (needs `respip` in
`module-config`), `block_a` / `block_aaaa` local zones (new in 1.26.0 —
available to us now), and `ratelimit:` / `ip-ratelimit:`.

**Why here:** on a fragile censored uplink, ad/tracker/malware domains are
a large share of requests, and with `serve-expired` plus an aggressive
cache, blocking is nearly free.

**Difficulty:** low.

---

## [P2] — track, do not build

- **Post-quantum DNS.** The 2026 work is COSE/JOSE encoding for PQ
  signatures (draft-ietf-cose-post-quantum-signatures), not a settled
  DNSSEC successor. There is no deployable QSIG-equivalent to adopt.
- **DNSCrypt v2 in unbound.** Supported by the binary, but DoT/853 is
  blocked on this link, so it buys nothing today. Revisit if egress
  changes.
- **DNS-over-CoAP** (draft-ietf-core-dns-over-coap-20) — IoT only.
- **SVCB RR tunnel** (draft-eastlake-dnsop-svcb-rr-tunnel-09) — an
  SNI-free way to publish egress endpoints in DNS. Watch.
- **DNSSEC automation / CDS-CDNSKEY multi-signer**
  (draft-ietf-dnsop-dnssec-automation-05) — relevant to the DNSSEC-off
  problem, since Tor strips RRSIG and strict validation cannot complete.
- **Compact Denial of Existence** (draft-ietf-dnsop-compact-denial-of-
  existence) — on-demand NSEC, avoids zone disclosure when serving
  authoritative data under surveillance.

---

## How this list was produced, and its known weaknesses

Findings came from a research subagent whose web-search backend was
partly broken, so most sources were fetched directly from the GitHub REST
API, `datatracker.ietf.org`, `export.arxiv.org` and NIST NVD through the
local proxy. That path works; ordinary search does not on this host.

Two cautions carried forward from this session:

- **Several items in the original report were already stale on arrival** —
  it described unbound 1.24.2 and unregistered Xray/Hysteria/sing-box,
  both of which had been fixed earlier the same day. Everything here was
  re-verified against the live system before being written down.
- **Two of its secondary sources were flagged as needing primary
  confirmation.** The AI-Now "Friendly Fire" / "HalluSquatting" papers on
  agent risk should be read directly before acting on the
  auto-approve/allowlist guidance.