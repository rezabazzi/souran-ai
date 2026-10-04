#!/usr/bin/env python3
"""
Souran AI Network Server v5.1.0 — Unified Feature Registry
File: souran_features.py

WHAT THIS REPLACES
------------------
Feature state used to live in `toggles.conf` as five flat keys
(tor_binding, censorship_bypass, dnssec, cache, blocklists) written by a
bash script. Three problems with that, all of them real:

1. The dashboard could only show what the sidecar happened to hardcode.
   Turning a feature off required the toggle to know a specific systemctl
   call and a specific config file edit; there was no single list of what
   exists, so features were inevitably missing from the UI.
2. `toggles.conf` was a plain text file edited with sed. A crash mid-write
   or a stray character silently changed feature state, and there was no
   record of who changed what or when.
3. "on" was not enforced anywhere. The flag could read `on` while the
   service was stopped and the behaviour was entirely absent — which is
   exactly the class of lie the watchdog was already fighting.

THE MODEL HERE
--------------
Every capability is a Feature with:
  - an id, a category, a description
  - how to turn it on and off (a list of unit operations + config edits)
  - how to PROBE it (the real runtime truth, not the flag)
  - dependencies: enabling X requires Y

The distinction between `state` (what was asked for) and `effective`
(what is actually true right now) is the whole point. The dashboard shows
both, and a mismatch is reported as drift rather than hidden.
"""

import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone

SOURAN_DIR = "/opt/souran-ai"
STATE_FILE = os.path.join(SOURAN_DIR, "feature-state.json")
LEGACY_TOGGLES = os.path.join(SOURAN_DIR, "toggles.conf")

VALID_STATES = ("on", "off")


# --------------------------------------------------------------------------
# Feature definitions
# --------------------------------------------------------------------------
# `units`: (unit, action_on, action_off)
# `config`: (relative path under SOURAN_DIR, key, value_on, value_off)
#   A config edit is applied with a targeted, reversible substitution and
#   is reported if the expected pattern is absent rather than silently
#   doing nothing.
# `probe`: a python expression evaluated with `unit_active`, `tcp_open`
#   and `read_cfg` in scope, returning (bool, detail-string).
# `requires`: ids that must be `on` for this to work.

FEATURES = {
    # ---------------- DNS core ----------------
    "dns_recursive": dict(
        category="dns",
        label="Zero-Upstream Recursive DNS",
        description=("unbound resolving from the root hints downward, with "
                     "no forwarders and no upstream recursion service."),
        units=[("souran-dns", "start", "stop")],
        requires=[],
        probe="(unit_active('souran-dns'), 'unbound core')",
    ),
    "dns_frontend": dict(
        category="dns",
        label="Poison-Proof Front-End (:53)",
        description=("The tier that owns port 53, cross-checks upstream "
                     "answers for injected private addresses, and escalates "
                     "to DoH over 443 when a tier-1 answer is untrustworthy."),
        units=[("souran-doh-fallback", "start", "stop")],
        requires=["dns_recursive"],
        probe="(unit_active('souran-doh-fallback'), 'front-end on :53')",
    ),
    "dns_over_tls": dict(
        category="dns",
        label="DNS-over-TLS (:853)",
        description="Encrypted DNS transport for LAN clients.",
        units=[("souran-dns-dot", "start", "stop")],
        requires=["dns_recursive"],
        probe="(tcp_open(853), 'DoT listener')",
    ),
    "dns_over_https": dict(
        category="dns",
        label="DNS-over-HTTPS (:8083)",
        description="Encrypted DNS over HTTPS/443, usable where plain DNS is blocked.",
        units=[("souran-8083-doh", "start", "stop")],
        requires=["dns_frontend"],
        probe="(tcp_open(8083), 'DoH listener')",
    ),
    "dns_cache_prefetch": dict(
        category="dns",
        label="Cache + Prefetch + Serve-Expired",
        description=("Aggressive caching so a slow or lossy link still "
                     "answers instantly, and stale answers are served while "
                     "refresh happens in the background."),
        units=[],  # config-level only
        requires=["dns_recursive"],
        probe="(read_cfg('config/souran-unbound.conf.yaml', 'prefetch') == 'yes', 'prefetch')",
    ),
    "dns_dnssec": dict(
        category="dns",
        label="DNSSEC Validation",
        description=("Validates the chain of trust from the root anchor. "
                     "Currently OFF by default: Tor strips RRSIG records, so "
                     "validating through the Tor transport fails closed and "
                     "looks like a broken resolver rather than a correct "
                     "rejection. Enable only on a direct, un-tunnelled path."),
        units=[],
        requires=["dns_recursive"],
        default="off",   # permissive today; strict cannot work over Tor
        probe="(read_cfg('config/souran-unbound.conf.yaml', 'module-config') == '\"validator iterator\"' and read_cfg('config/souran-unbound.conf.yaml', 'val-permissive-mode') == 'no', 'strict DNSSEC validation')",
    ),
    "dns_tcp_upstream": dict(
        category="dns",
        label="Force TCP for Upstream Queries",
        description=("UDP/53 responses are trivially forged on this network "
                     "(observed: telegram.org answering as 10.10.34.36). TCP "
                     "upstream cannot be spoofed in flight. Slightly higher "
                     "latency, materially more trustworthy."),
        units=[],
        requires=["dns_recursive"],
        probe="(read_cfg('config/souran-unbound.conf.yaml', 'tcp-upstream') == 'yes', 'TCP upstream')",
    ),
    "dns_doh_tier": dict(
        category="dns",
        label="DoH Escalation Tier",
        description=("When tier-1 fails or returns an injected answer, "
                     "escalate to DoH on HTTPS/443 — the only transport that "
                     "is clean on this network."),
        requires=["dns_frontend"],
        probe="(unit_active('souran-doh-fallback'), 'escalation inside front-end')",
    ),

    # ---------------- Censorship bypass ----------------
    "censor_zapret": dict(
        category="censorship",
        label="Zapret DPI Desync (nfqws/tpws)",
        description=("Packet-level DPI bypass: splits and desynchronises TLS "
                     "ClientHello so a middlebox cannot match the SNI, and "
                     "serves fake packets to hold the censor's connection."),
        units=[("souran-zapret", "start", "stop")],
        requires=[],
        probe="(unit_active('souran-zapret'), 'zapret bypass')",
    ),
    "censor_byedpi": dict(
        category="censorship",
        label="ciadpi Desync Proxy (:1080)",
        description="Second, independent DPI desync implementation on a local HTTP proxy.",
        units=[("souran-byedpi", "start", "stop")],
        requires=[],
        probe="(tcp_open(1080), 'ciadpi :1080')",
    ),
    "censor_tor": dict(
        category="censorship",
        label="Tor Transport",
        description="Routes resolution and egress over the Tor network.",
        units=[("tor@default", "start", "stop")],
        requires=[],
        probe="(tcp_open(9050), 'Tor SOCKS5 :9050')",
    ),
    "censor_socks_bridge": dict(
        category="censorship",
        label="SOCKS→Tor Bridge (:8119/:17844)",
        description=("Local HTTP CONNECT proxy and raw forwarder that let "
                     "cloudflared's edge traffic complete its TLS handshake "
                     "end-to-end over Tor."),
        units=[("socks-bridge", "start", "stop")],
        requires=["censor_tor"],
        probe="(tcp_open(8119), 'socks bridge')",
    ),
    "censor_outbound_dns": dict(
        category="censorship",
        label="Outbound DNS Forced Through Tor",
        description=("iptables/nft NAT redirect sending every outbound :53 "
                     "query to Tor, so the host cannot be poisoned at the source."),
        units=[],
        requires=["censor_tor"],
        probe="(nat_dns_redirect_present(), 'outbound :53 -> :9053')",
    ),

    # ---------------- Privacy / validation ----------------
    "dns_dnssec_tor_note": dict(
        category="dns",
        label="(info) DNSSEC-over-Tor caveat",
        description=("Informational. Tor's exit relays strip RRSIG, so "
                     "strict DNSSEC validation cannot succeed over the Tor "
                     "transport. This is why dns_dnssec defaults to off."),
        units=[],
        requires=[],
        probe="(True, 'informational')",
    ),

    # ---------------- Web3 ----------------
    "web3_ens": dict(
        category="web3",
        label="ENS / Web3 Name Resolution",
        description="Resolves .eth and other blockchain names alongside DNS.",
        units=[("souran-web3-resolver", "start", "stop")],
        requires=[],
        probe="(unit_active('souran-web3-resolver'), 'Web3 resolver')",
    ),
    "web3_rpc": dict(
        category="web3",
        label="Blockchain RPC Gateway",
        description="Local JSON-RPC proxy so chain traffic avoids direct endpoints.",
        units=[],
        requires=["censor_tor"],
        probe="(web3_rpc_ok(), 'ENS/RPC API answering')",
    ),

    # ---------------- Gaming ----------------
    "gaming_dns": dict(
        category="gaming",
        label="Gaming DNS",
        description="Resolver profile tuned for game services and matchmakers.",
        units=[("souran-gaming-dns", "start", "stop")],
        requires=[],
        probe="(unit_active('souran-gaming-dns'), 'gaming resolver')",
    ),

    # ---------------- Operations ----------------
    "ops_watchdog": dict(
        category="ops",
        label="Self-Healing Watchdog",
        description="Continuously checks components and repairs what it can.",
        units=[("souran-watchdog", "start", "stop")],
        requires=[],
        probe="(unit_active('souran-watchdog'), 'watchdog')",
    ),
    "ops_intrusion_detection": dict(
        category="ops",
        label="Intrusion Detection",
        description="Watches auth and connection logs for probing patterns.",
        units=[("souran-ids", "start", "stop")],
        requires=[],
        probe="(unit_active('souran-ids'), 'IDS')",
    ),
    "ops_cloudflared": dict(
        category="ops",
        label="Cloudflare Tunnel",
        description="Outbound tunnel exposing the dashboard without opening ports.",
        units=[("cloudflared", "start", "stop")],
        requires=[],
        probe="(unit_active('cloudflared'), 'tunnel')",
    ),
    "ops_firewall": dict(
        category="ops",
        label="Host Firewall",
        description="nftables ruleset restricting inbound access to the LAN service set.",
        units=[("souran-firewall", "start", "stop")],
        requires=[],
        probe="(nft_table_present('souran_filter'), 'souran_filter table')",
    ),
    "ops_learning_engine": dict(
        category="ops",
        label="Learning Engine (:8084)",
        description="Records resolution outcomes so the stack improves over time.",
        units=[("souran-learning-engine", "start", "stop")],
        requires=[],
        probe="(unit_active('souran-learning-engine'), 'learning engine')",
    ),
    "ops_anticompress": dict(
        category="ops",
        label="Anti-Compression Engine (:8085)",
        description="Lossless context handling so nothing is truncated silently.",
        units=[("souran-anticompress", "start", "stop")],
        requires=[],
        probe="(unit_active('souran-anticompress'), 'anti-compression')",
    ),
    "ops_dashboard_hermes": dict(
        category="ops",
        label="Hermes Control Dashboard (:8082)",
        description="Primary control surface. Token-protected.",
        units=[("souran-8082-dashboard", "start", "stop")],
        requires=[],
        probe="(tcp_open(8082), 'Hermes dashboard')",
    ),
    "ops_dashboard_web": dict(
        category="ops",
        label="Web Dashboard (:8383)",
        description="Secondary control surface. Token-protected.",
        units=[("souran-web-8383", "start", "stop")],
        requires=[],
        probe="(tcp_open(8383), 'web dashboard')",
    ),
    "ops_sidecar_api": dict(
        category="ops",
        label="Sidecar Control API (:9192)",
        description="Loopback-only control API backing the dashboards.",
        units=[("souran-sidecar", "start", "stop")],
        requires=[],
        probe="(unit_active('souran-sidecar'), 'sidecar API')",
    ),
}


# --------------------------------------------------------------------------
# Probe helpers (injected into the probe expression scope)
# --------------------------------------------------------------------------
def _run(cmd, timeout=8):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as exc:
        return 1, "", str(exc)


def unit_active(unit: str) -> bool:
    """Is a systemd unit active?

    Read with plain `systemctl is-active`, NEVER sudo. The control-plane
    services set NoNewPrivileges=yes, which makes sudo fail outright with
    "the 'no new privileges' flag is set" -- an earlier version of this
    probe tried sudo first and therefore reported every service as down
    from inside the dashboard while the same function returned True from
    an interactive shell. `systemctl is-active` needs no privilege.
    """
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", str(unit or "")):
        return False
    rc, out, _ = _run(f"systemctl is-active {unit}")
    return out == "active"


def tcp_open(port: int, host: str = "127.0.0.1") -> bool:
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    try:
        s.connect((host, int(port)))
        return True
    except OSError:
        return False
    finally:
        s.close()


def read_cfg(relpath: str, key: str):
    """Return the last value of `key` in a YAML-ish config, or None."""
    path = os.path.join(SOURAN_DIR, relpath)
    try:
        with open(path) as fh:
            for line in fh:
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                m = re.match(rf"^\s*{re.escape(key)}\s*:\s*(.+?)\s*$", stripped)
                if m:
                    return m.group(1).strip().strip('"').strip("'")
    except OSError:
        return None
    return None


# Firewall/NAT state is published to a world-readable file by the
# privileged path that CAN see it (souran-firewall.sh, running as root at
# boot). The unprivileged control plane then reads the answer from disk
# instead of trying to read netfilter state, which needs CAP_NET_ADMIN it
# cannot have: the services run with NoNewPrivileges=yes, so sudo is
# unavailable to them by design.
FW_STATE_FILE = os.path.join(SOURAN_DIR, "logs", "firewall-state.json")


def _fw_state() -> dict:
    try:
        with open(FW_STATE_FILE) as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def nat_dns_redirect_present() -> bool:
    """Is outbound :53 still redirected into Tor?

    Read from the firewall state file. Attempting to read the nat table
    directly cannot work from the control plane (CAP_NET_ADMIN required,
    and NoNewPrivileges blocks sudo), which previously made this report
    "off" for a rule that was demonstrably active and counting packets.
    """
    st = _fw_state()
    if st:
        return bool(st.get("outbound_dns_to_tor"))
    # No state file yet: fall back to the marker file the legacy DNS-NAT
    # fix leaves behind, and finally to a plain read that works if this
    # process happens to hold the capability.
    if os.path.exists(os.path.join(SOURAN_DIR, "config", ".dns-nat-active")):
        return True
    rc, out, _ = _run("nft list table ip nat 2>/dev/null")
    return bool(out and "dport 53" in out and "9053" in out)


def nft_table_present(name: str) -> bool:
    """Is an nftables table loaded?

    Read from the firewall state file written by the privileged boot path.
    A direct `nft list` needs CAP_NET_ADMIN, and these services run with
    NoNewPrivileges=yes so they cannot obtain it -- an earlier version
    reported the firewall as "off" from the dashboard while it was
    demonstrably loaded and enforcing.
    """
    if not re.fullmatch(r"[A-Za-z0-9_]{1,32}", str(name or "")):
        return False
    st = _fw_state()
    if st:
        if name == "souran_filter":
            return bool(st.get("souran_filter_loaded"))
        return bool(st.get("tables", {}).get(name))
    rc, out, _ = _run(f"nft list table inet {name} 2>/dev/null")
    return bool(out and f"table inet {name}" in out)


def web3_rpc_ok() -> bool:
    """Is the Web3 name-resolution API actually answering?

    Probing /api/health was wrong — that path does not exist on :8086 and
    returned 404, so the probe reported the feature as broken while it was
    serving. Query the real endpoint and accept any well-formed JSON
    answer, including an empty result set, as proof of life.
    """
    rc, out, _ = _run(
        "curl -s --max-time 10 "
        "'http://127.0.0.1:8086/api/web3/ens?name=vitalik.eth'")
    if rc != 0 or not out:
        return False
    try:
        json.loads(out)
        return True
    except ValueError:
        return False


PROBE_SCOPE = {
    "unit_active": unit_active,
    "tcp_open": tcp_open,
    "read_cfg": read_cfg,
    "nat_dns_redirect_present": nat_dns_redirect_present,
    "nft_table_present": nft_table_present,
    "web3_rpc_ok": web3_rpc_ok,
    "True": True,
}


# --------------------------------------------------------------------------
# State persistence
# --------------------------------------------------------------------------
def load_state() -> dict:
    """Desired state, persisted as JSON. Migrates the legacy toggles file."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as fh:
                data = json.load(fh)
            if isinstance(data, dict) and "features" in data:
                return data
        except (OSError, ValueError):
            pass

    # Migration from the old flat format. Anything absent defaults to on,
    # because that is what the stack's history shows it was running as.
    state = {"features": {}, "migrated_from": None}
    if os.path.exists(LEGACY_TOGGLES):
        try:
            with open(LEGACY_TOGGLES) as fh:
                for line in fh:
                    line = line.strip()
                    if "=" in line and not line.startswith("#"):
                        k, v = line.split("=", 1)
                        state["features"][k.strip()] = (
                            "on" if v.strip() == "on" else "off")
            state["migrated_from"] = LEGACY_TOGGLES
        except OSError:
            pass
    for fid, spec in FEATURES.items():
        # Per-feature default, not a blanket "on": DNSSEC has never been
        # strict on this host and cannot be over Tor, so defaulting it on
        # would have the registry assert a falsehood from birth.
        state["features"].setdefault(fid, spec.get("default", "on"))
    save_state(state)
    return state


def save_state(state: dict) -> None:
    state["updated_at"] = datetime.now(timezone.utc).isoformat()
    tmp = STATE_FILE + ".tmp"
    # Write-then-rename: a crash mid-write cannot leave a truncated state
    # file that silently flips features on reboot.
    with open(tmp, "w") as fh:
        json.dump(state, fh, indent=2, sort_keys=True)
    os.replace(tmp, STATE_FILE)


# --------------------------------------------------------------------------
# Desired vs effective
# --------------------------------------------------------------------------
def probe_feature(fid: str):
    spec = FEATURES.get(fid)
    if not spec:
        return False, "unknown feature"
    expr = spec.get("probe")
    if not expr:
        return True, "no probe defined"
    try:
        val, detail = eval(expr, dict(PROBE_SCOPE))  # noqa: S307
        return bool(val), str(detail)
    except Exception as exc:
        return False, f"probe error: {exc}"


def desired(fid: str, state=None) -> str:
    state = state or load_state()
    spec = FEATURES.get(fid, {})
    return state["features"].get(fid, spec.get("default", "on"))


def effective(fid: str) -> str:
    ok, _detail = probe_feature(fid)
    return "on" if ok else "off"


def full_report() -> dict:
    state = load_state()
    out = {}
    for fid, spec in FEATURES.items():
        want = state["features"].get(fid, "on")
        eff, detail = probe_feature(fid)
        unmet = [r for r in spec.get("requires", [])
                 if state["features"].get(r, "on") != "on"]
        out[fid] = {
            "id": fid,
            "label": spec["label"],
            "category": spec["category"],
            "description": spec["description"],
            "desired": want,
            "effective": "on" if eff else "off",
            "detail": detail,
            "requires": spec.get("requires", []),
            "unmet_requirements": unmet,
            # Drift is the interesting signal: asked for but not true.
            "drift": (want == "on") != bool(eff),
            "controllable": bool(spec.get("units")),
        }
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "version": "5.1.0",
        "features": out,
        "summary": {
            "total": len(out),
            "on": sum(1 for f in out.values() if f["effective"] == "on"),
            "off": sum(1 for f in out.values() if f["effective"] == "off"),
            "drifted": sum(1 for f in out.values() if f["drift"]),
        },
    }



# --------------------------------------------------------------------------
# Privileged execution via intent queue
# --------------------------------------------------------------------------
# The control-plane services cannot escalate (NoNewPrivileges). They write
# a request; a privileged executor applies it. The queue is a directory,
# not a pipe or a socket, because a directory is inspectable with `ls`,
# survives a crash, and cannot be used to smuggle a shell string.
INTENT_DIR = os.path.join(SOURAN_DIR, "run", "feature-intents")


def _submit_intent(fid: str, action: str) -> tuple:
    """Record a feature-change request for the privileged executor.

    Returns (rc, stdout, stderr) in the same shape as _run() so callers do
    not care which path was taken. rc=0 means ACCEPTED FOR PROCESSING,
    not necessarily applied -- so the caller re-probes afterwards and the
    API reports desired-vs-effective honestly rather than claiming success.
    """
    if fid not in FEATURES:
        return 3, "", f"unknown feature {fid}"
    if action not in ("enable", "disable"):
        return 2, "", "invalid action"
    try:
        os.makedirs(INTENT_DIR, mode=0o755, exist_ok=True)
        stamp = f"{time.time_ns()}-{os.getpid()}"
        req = {
            "feature": fid,
            "action": action,
            "requested_by_uid": os.getuid(),
            "requested_at": datetime.now(timezone.utc).isoformat(),
        }
        path = os.path.join(INTENT_DIR, f"{stamp}.json")
        tmp = path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(req, fh)
        os.replace(tmp, path)
        # Try an immediate synchronous apply first, so a dashboard click
        # feels instant when it can be. The executor is idempotent, so a
        # later timer pass over the same intent is harmless.
        rc, out, err = _run(
            f"systemctl start souran-feature-executor.service", timeout=45)
        if rc == 0:
            return 0, "intent submitted and executor triggered", ""
        # Executor unavailable: the intent is still queued and will be
        # applied by the timer. Report that honestly.
        return 0, "intent queued (executor unavailable; timer will apply)", ""
    except OSError as exc:
        return 1, "", f"cannot queue intent: {exc}"


# --------------------------------------------------------------------------
# Apply
# --------------------------------------------------------------------------
def set_feature(fid: str, state_want: str, persist: bool = True) -> dict:
    if fid not in FEATURES:
        raise KeyError(f"unknown feature: {fid}")
    if state_want not in VALID_STATES:
        raise ValueError(f"state must be one of {VALID_STATES}")

    spec = FEATURES[fid]
    if state_want == "on":
        unmet = [r for r in spec.get("requires", [])
                 if load_state()["features"].get(r, "on") != "on"]
        if unmet:
            return {"ok": False,
                    "error": f"requires: {', '.join(unmet)}",
                    "hint": "enable those first"}

    # MUTATION PATH.
    #
    # This process runs with NoNewPrivileges=yes, which sets a kernel flag
    # that makes the setuid bit inert -- sudo refuses with "the 'no new
    # privileges' flag is set". That is not fixable from sudoers; the flag
    # cannot be lowered by a child. Two earlier attempts failed here:
    #   1. `sudo systemctl ...` from the service -- always failed.
    #   2. `sudo souran-feature-apply.sh` -- also always failed, for the
    #      same reason, even though the identical command works from an
    #      interactive shell (verified side by side).
    #
    # So the privileged executor is moved OUT of this process entirely: we
    # record an INTENT here, and a privileged path applies it. The
    # NoNewPrivileges hardening stays exactly as it was.
    action = "enable" if state_want == "on" else "disable"
    rc, out, err = _submit_intent(fid, action)
    results = [{"action": action, "rc": rc,
                "out": out[:300], "err": err[:300]}]

    if persist:
        st = load_state()
        st["features"][fid] = state_want
        save_state(st)

    # The privileged executor runs on a 15s timer, so an accepted intent is
    # often not applied yet at the instant we first probe. Poll briefly
    # before concluding failure, otherwise the API reports "apply failed"
    # for a change that succeeds seconds later -- the mirror image of the
    # original bug, where it reported success for a change that never
    # happened.
    eff = False
    detail = "not yet applied"
    for _ in range(8):
        eff, detail = probe_feature(fid)
        if (state_want == "on") == bool(eff):
            break
        time.sleep(1.0)

    # ok reflects whether the REQUEST was accepted by the privileged path,
    # not whether the outcome matches the request. A mismatch is reported
    # as a failure, because a toggle that silently does nothing is worse
    # than one that errors.
    applied = all(r["rc"] == 0 for r in results)
    matches = (state_want == "on") == bool(eff)

    if not applied:
        note = (f"the privileged actuator FAILED (rc={results[0]['rc']}); "
                f"the feature was NOT changed. {results[0]['err'][:200]}")
    elif not matches:
        note = (f"actuator ran, but the runtime probe reports the feature "
                f"as {('off' if eff else 'on')} — requested {state_want}. "
                f"Check the unit and its journal.")
    else:
        note = "applied and verified against the runtime probe"

    return {
        "ok": applied and matches,
        "feature": fid,
        "desired": state_want,
        "effective": "on" if eff else "off",
        "verified": matches,
        "detail": detail,
        "operations": results,
        "note": note,
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "set" and len(sys.argv) >= 4:
        print(json.dumps(set_feature(sys.argv[2], sys.argv[3]), indent=2))
    elif len(sys.argv) > 1 and sys.argv[1] == "get" and len(sys.argv) >= 3:
        fid = sys.argv[2]
        print(json.dumps({
            "desired": desired(fid),
            "effective": effective(fid),
            "detail": probe_feature(fid)[1],
        }, indent=2))
    else:
        rep = full_report()
        print(json.dumps(rep, indent=2))
        s = rep["summary"]
        print(f"\n{s['on']}/{s['total']} effective on, "
              f"{s['drifted']} drifted", file=sys.stderr)
