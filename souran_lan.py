#!/usr/bin/env python3
"""
Souran AI Network Server v5.1.0 — LAN name service

File: souran_lan.py | Generates unbound local-zone + local-data rules so
LAN hosts resolve by name, and IPs resolve back to names.

WHY THIS EXISTS
---------------
This resolver answers for the whole LAN on :53. Clients on it need:

  * their own names to resolve  (printer.local -> 10.103.26.87)
  * their own IPs to reverse    (10.103.26.87 -> printer.local)
  * DHCP-leased names to follow the lease file

A Technitium audit concluded those two capabilities were genuinely
missing from the resolver, and that the right implementation is native
unbound rules rather than a second .NET DNS server. This is that
implementation.

HONEST ABOUT WHAT IT KNOWS
--------------------------
Sources, in order of authority:

  1. /etc/souran/lan-hosts.conf   -- explicit, operator-maintained
  2. /etc/hosts                   -- this host itself
  3. dnsmasq lease file            -- only if non-empty
  4. the host's own interfaces      -- so souran.souran.lan resolves

A name that is not in one of those is NOT invented. In particular, with
no DHCP server running and an empty lease file, this generates a zone
containing exactly one host -- this machine -- rather than a plausible-
looking list of neighbours that do not exist. That distinction is the
whole point: a reverse zone full of guesses is worse than none, because
PTR lies are trusted by monitoring and backup software.

Usage:
    souran_lan.py status      what is served, and from where
    souran_lan.py add HOST IP  add or update a host
    souran_lan.py remove HOST  remove a host
    souran_lan.py compile     regenerate the rules (done automatically)
"""

import argparse
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
from datetime import datetime, timezone

CONF = "/opt/souran-ai/config/souran-unbound.conf.yaml"
ZONE_FILE = "/opt/souran-ai/config/blocklists/lan.conf"
HOSTS_CONF = "/etc/souran/lan-hosts.conf"
LEASE_FILES = ["/var/lib/misc/dnsmasq.leases",
               "/var/lib/dhcp/dhcpd.leases",
               "/var/lib/NetworkManager/dnsmasq-leases.leases"]
STATE = "/opt/souran-ai/logs/lan-state.json"
DOMAIN = "souran.lan"


def log(msg):
    print(f"[souran-lan] {msg}", flush=True)


def _ptr_to_ip(ptr):
    """in-addr.arpa name back to an IP. Handles v4 and v6."""
    name = ptr.rstrip(".")
    if name.endswith("in-addr.arpa"):
        return ".".join(reversed(name[:-len(".in-addr.arpa")].split(".")))
    if name.endswith("ip6.arpa"):
        nib = "".join(reversed(name[:-len(".ip6.arpa")].split(".")))
        return str(ipaddress.IPv6Address(
            int(nib, 16) if nib else 0))
    raise ValueError(f"not a reverse name: {ptr}")


def _is_valid_name(n):
    return bool(re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
                             r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*",
                             n))


def read_operator_hosts():
    """Explicit operator entries. Comments and blanks allowed."""
    out = {}
    if not os.path.exists(HOSTS_CONF):
        return out
    with open(HOSTS_CONF) as fh:
        for ln, line in enumerate(fh, 1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = re.split(r"[\s\t]+", line)
            if len(parts) < 2:
                log(f"{HOSTS_CONF}:{ln} ignored: expected 'name ip'")
                continue
            name, ip = parts[0].lower(), parts[1]
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                log(f"{HOSTS_CONF}:{ln} ignored: '{ip}' is not an IP")
                continue
            if not _is_valid_name(name):
                log(f"{HOSTS_CONF}:{ln} ignored: '{name}' is not a hostname")
                continue
            out[name] = str(addr)
    return out


def read_etc_hosts():
    out = {}
    try:
        with open("/etc/hosts") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = re.split(r"[\s\t]+", line)
                if len(parts) < 2:
                    continue
                ip = parts[0]
                try:
                    addr = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                for name in parts[1:]:
                    n = name.lower()
                    if not _is_valid_name(n):
                        continue
                    # Skip loopback, link-local, multicast, unspecified,
                    # and the ip6-* / localhost boilerplate. Clients
                    # resolve those themselves, and a LAN zone listing
                    # ip6-allnodes -> ff02::1 is noise dressed as data.
                    if (addr.is_loopback or addr.is_link_local
                            or addr.is_multicast or addr.is_unspecified):
                        continue
                    if n == "localhost" or n.startswith("ip6-"):
                        continue
                    out[n] = str(addr)
    except OSError:
        pass
    return out


def read_leases():
    """DHCP leases, if any. Empty lease file yields nothing -- which is
    the normal case here, and is reported rather than papered over."""
    out = {}
    files = [p for p in LEASE_FILES if os.path.exists(p)
             and os.path.getsize(p) > 0]
    for path in files:
        try:
            with open(path) as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    ip, name = parts[0], parts[3]
                    try:
                        addr = ipaddress.ip_address(ip)
                    except ValueError:
                        continue
                    if name == "*" or not _is_valid_name(name.lower()):
                        continue
                    out[name.lower()] = str(addr)
        except OSError:
            continue
    return out, files


def collect():
    """Merge every source. Operator entries win over inferred ones."""
    leases, lease_files = read_leases()
    sources = {
        "operator": read_operator_hosts(),
        "etc_hosts": read_etc_hosts(),
        "dhcp_leases": leases,
    }
    merged = {}
    for src in ("dhcp_leases", "etc_hosts", "operator"):
        for n, ip in sources[src].items():
            merged[n] = ip
    # This host's own interfaces, under the local domain.
    own = {}
    host = socket.gethostname().split(".")[0].lower()
    try:
        import subprocess as _sp
        out = _sp.run(["ip", "-4", "-o", "addr", "show", "scope", "global"],
                       capture_output=True, text=True, timeout=20).stdout
        for line in out.splitlines():
            parts = line.split()
            if "inet" not in parts:
                continue
            # `ip -o` prints CIDR ("10.103.26.86/24"). Passing that
            # straight to ip_address() raises ValueError, which the
            # surrounding except swallowed -- so own-interface detection
            # silently produced nothing and every name vanished from the
            # zone. Strip the prefix.
            cidr = parts[parts.index("inet") + 1]
            addr = ipaddress.ip_address(cidr.split("/", 1)[0])
            # The routable address is the useful one; the docker bridges
            # are private but not LAN-facing, so prefer the first that is
            # on the subnet the firewall actually serves.
            if addr.is_loopback or addr.is_link_local:
                continue
            own[host] = str(addr)
            break
    except (OSError, ValueError, IndexError, _sp.SubprocessError) as exc:
        log(f"own-interface detection failed: {exc}")
    for n, ip in own.items():
        merged.setdefault(n, ip)
        merged.setdefault(f"{n}.{DOMAIN}", ip)
    return merged, sources, lease_files


def compile(dry_run=False):
    merged, sources, lease_files = collect()

    # Build the forward records from a CANONICAL name->ip map, expanding
    # each host to at most two names: the bare name and name.souran.lan.
    #
    # The earlier version walked the merged dict, which already contained
    # the qualified form, and re-qualified it -- producing
    # souran.souran.lan.souran.lan in both the forward and the PTR
    # records. Canonicalising once, here, is what prevents that.
    # Canonical name -> ip. A name that already carries ANY domain is
    # left alone; only a bare label gains the .souran.lan suffix.
    #
    # Two bugs came from doing this more than once:
    #   souran -> souran.souran.lan, then that got re-qualified into
    #            souran.souran.lan.souran.lan
    #   router.lan -> router.lan.souran.lan, which is meaningless
    # So: derive the FQDN list from the canonical BARE name only, and
    # only add the suffix when the name has no dot in it.
    canon = {}
    for name, ip in merged.items():
        bare = name.rstrip(".").lower()
        if not bare:
            continue
        canon[bare] = ip
    # Collapse the host's own two spellings ("souran" and
    # "souran.souran.lan") into the bare name, which is the one the
    # expansion below knows how to qualify exactly once.
    # Iterate: a key that was already written as souran.souran.lan
    # .souran.lan needs TWO passes to unwind to "souran". A single pass
    # only removes one layer and leaves the compounded key behind.
    changed = True
    while changed:
        changed = False
        for bare in list(canon):
            if bare.endswith("." + DOMAIN):
                short = bare[: -(len(DOMAIN) + 1)]
                if short in canon and canon[short] == canon[bare]:
                    canon.pop(bare)
                    changed = True

    fwd = []
    seen_fwd = set()
    for bare, ip in sorted(canon.items()):
        if not _is_valid_name(bare):
            continue
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_loopback or addr.is_link_local:
            continue
        rtype = "AAAA" if addr.version == 6 else "A"
        names = [bare] if "." in bare else [bare, f"{bare}.{DOMAIN}"]
        for n in names:
            fq = n.rstrip(".") + "."
            if fq in seen_fwd:
                continue
            seen_fwd.add(fq)
            fwd.append((fq, n, ip, rtype))

    rev = []
    seen_rev = {}
    for bare, ip in sorted(canon.items()):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        # PTR only for private/ULA space. Answering PTR for a public
        # address would make this a small forgery generator.
        if addr.version == 4 and not addr.is_private:
            continue
        if addr.version == 6 and not (addr.is_private or addr.is_link_local):
            continue
        target = bare if "." in bare else f"{bare}.{DOMAIN}"
        ptr = str(addr.reverse_pointer) + "."
        # One PTR per address: the first name wins, and later aliases for
        # the same address do not overwrite it.
        seen_rev.setdefault(ptr, target)
    for ptr, target in sorted(seen_rev.items()):
        rev.append((ptr, target + "."))

    log(f"hosts: {len(canon)} names, {len(fwd)} forward records, "
        f"{len(rev)} reverse records")
    log(f"sources: operator={len(sources['operator'])} "
        f"etc_hosts={len(sources['etc_hosts'])} "
        f"leases={len(sources['dhcp_leases'])}"
        + (f" (from {', '.join(os.path.basename(f) for f in lease_files)})"
           if lease_files else " (no lease file has content)"))
    if not canon:
        log("nothing known -- writing an empty ruleset rather than guesses")

    if dry_run:
        for fq, _b, ip, rt in fwd:
            log(f"  [dry] {fq} {rt} {ip}")
        for ptr, tgt in rev:
            log(f"  [dry] {ptr} PTR {tgt}")
        return {"domains": len(canon), "forward": len(fwd),
                "reverse": len(rev)}

    os.makedirs(os.path.dirname(ZONE_FILE), exist_ok=True)
    tmp = ZONE_FILE + ".tmp"
    with open(tmp, "w") as fh:
        fh.write("# Generated by souran_lan.py -- do not edit.\n")
        fh.write(f"# {len(canon)} names, "
                 f"{datetime.now(timezone.utc).isoformat()}\n")
        fh.write("# Only names with a real source are listed. No guesses.\n")
        fh.write(f'local-zone: "{DOMAIN}." static\n')
        # One static zone per BARE label. Without this the bare
        # "souran." record sits outside the .souran.lan zone, unbound
        # never consults it, and the name NXDOMAINs even though the
        # record is right there in the file.
        for bare in sorted({b for _fq, b, _ip, _rt in fwd}):
            if "." in bare:
                continue
            fh.write(f'local-zone: "{bare}." static\n')
        for fq, _b, ip, rt in sorted(fwd):
            fh.write(f'local-data: "{fq} {rt} {ip}"\n')
        for tld in ("in-addr.arpa", "ip6.arpa"):
            fh.write(f'local-zone: "{DOMAIN}.{tld}." static\n')
        for ptr, tgt in sorted(rev):
            fh.write(f'local-data: "{ptr} 3600 IN PTR {tgt}"\n')
    os.replace(tmp, ZONE_FILE)
    log(f"wrote {ZONE_FILE}")

    with open(STATE, "w") as fh:
        json.dump({"hosts": canon,
                   "reverse": {p: t for p, t in rev},
                   "counts": {k: len(v) for k, v in sources.items()},
                   "lease_files": lease_files,
                   "compiled_at": datetime.now(timezone.utc).isoformat()},
                  fh, indent=2)
    return {"domains": len(merged), "reverse": len(rev)}


def ensure_include():
    """Add a top-level include for the LAN zone.

    Refuses to add one unless the zone file exists: an include pointing
    at a missing file makes unbound-checkconf FAIL, which stops the
    resolver entirely. That is the sharpest edge in this whole feature.

    Same placement lesson as the blocklist: after a `remote-control:`
    block, an include parses as that block's sub-key. It goes before.
    """
    if not os.path.exists(CONF):
        return False
    with open(CONF) as fh:
        cur = fh.read()
    if "config/blocklists/lan.conf" in cur:
        return True
    if not os.path.exists(ZONE_FILE):
        log(f"not adding the include: {ZONE_FILE} does not exist")
        return False
    stanza = ('\n# LAN name service, generated by souran_lan.py.\n'
              '# Before remote-control: -- an include after that block\n'
              '# parses as its sub-key, not as a top-level include.\n'
              'include: "/opt/souran-ai/config/blocklists/lan.conf"\n')
    anchor = 'access-control: ::/0 allow\n'
    if anchor in cur:
        cur = cur.replace(anchor, anchor + stanza, 1)
    else:
        cur = cur.rstrip("\n") + "\n" + stanza
    with open(CONF, "w") as fh:
        fh.write(cur)
    log("added the LAN include to the unbound config")
    return True


def status():
    if not os.path.exists(ZONE_FILE):
        log("no LAN zone compiled yet")
        return 1
    state = {}
    if os.path.exists(STATE):
        try:
            with open(STATE) as fh:
                state = json.load(fh)
        except (OSError, ValueError):
            pass
    fwd = sum(1 for l in open(ZONE_FILE) if l.startswith("local-data:"))
    print(f"zone file : {ZONE_FILE}")
    print(f"  records : {fwd:,}")
    installed = (os.path.exists(CONF)
                 and "config/blocklists/lan.conf" in open(CONF).read())
    print(f"in config : {installed}")
    if state:
        print(f"compiled  : {state.get('compiled_at', '?')[:19]}")
        print(f"sources   : {state.get('counts')}")
        lf = state.get("lease_files") or []
        print(f"leases    : {[os.path.basename(f) for f in lf] or 'none with content'}")
        print("\nhosts:")
        for n, ip in sorted((state.get("hosts") or {}).items()):
            print(f"  {n:32} {ip}")
    return 0


def add(name, ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        log(f"'{ip}' is not an IP address")
        return 1
    if not _is_valid_name(name.lower()):
        log(f"'{name}' is not a valid hostname")
        return 1
    os.makedirs(os.path.dirname(HOSTS_CONF), exist_ok=True)
    lines = []
    if os.path.exists(HOSTS_CONF):
        with open(HOSTS_CONF) as fh:
            lines = [l for l in fh
                     if l.split("#", 1)[0].strip()
                     and l.split("#", 1)[0].split()[0].lower() != name.lower()]
    lines.append(f"{name.lower()} {addr}\n")
    with open(HOSTS_CONF, "w") as fh:
        fh.writelines(lines)
    log(f"{name.lower()} -> {addr}")
    return 0 if compile() else 1


def remove(name):
    if not os.path.exists(HOSTS_CONF):
        log("no operator host file")
        return 1
    with open(HOSTS_CONF) as fh:
        lines = fh.readlines()
    kept = [l for l in lines
            if l.split("#", 1)[0].strip()
            and l.split("#", 1)[0].split()[0].lower() != name.lower()]
    if len(kept) == len(lines):
        log(f"{name} was not in {HOSTS_CONF}")
        return 1
    with open(HOSTS_CONF, "w") as fh:
        fh.writelines(kept)
    log(f"removed {name}")
    return 0 if compile() else 1


def main(argv=None):
    ap = argparse.ArgumentParser(prog="souran_lan.py",
                                 description="LAN name service for unbound.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status").set_defaults(fn=lambda a: status())
    p = sub.add_parser("compile")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(fn=lambda a: ((compile(a.dry_run),
                                  ensure_include() if not a.dry_run else None)))
    p = sub.add_parser("add")
    p.add_argument("name")
    p.add_argument("ip")
    p.set_defaults(fn=lambda a: add(a.name, a.ip))
    p = sub.add_parser("remove")
    p.add_argument("name")
    p.set_defaults(fn=lambda a: remove(a.name))
    a = ap.parse_args(argv)
    r = a.fn(a)
    return 0 if r in (0, None, (None, None), ({}, True)) else 1


if __name__ == "__main__":
    sys.exit(main())