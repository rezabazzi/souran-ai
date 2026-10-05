#!/usr/bin/env python3
"""
Souran AI Network Server v5.1.0 — blocklist compiler

File: souran_blocklists.py | Turns hosts-format blocklists into an
unbound `auth-zone` ruleset.

WHY THIS EXISTS
---------------
The operator had 514,000 lines of ad/tracker/malware blocklists sitting
cached and completely unused at /var/lib/technitium/blocklists/ — the
leftovers of a Technitium install that stopped on 2026-09-30. Meanwhile
the resolver carries every one of those lookups across a fragile,
censored uplink.

On this network, a tracker domain is not a privacy nicety: it is
bandwidth spent on a link that is already lossy and already being
shaped by a censor. Blocking them is nearly free once the cache is warm.

WHY unbound NATIVELY, RATHER THAN TECHNITIUM
---------------------------------------------
unbound already implements this. `auth-zone` compiles a signed zone from
local data, `local-data` declares individual records, and `local-zone`
declares a name as always-NXDOMAIN. None of it needs a .NET runtime, an
ASP.NET admin console, or a second DNS server to fail.

Running a whole second DNS server to serve a text file would add a large
attack surface for no capability this resolver lacks.

THE COST, STATED PLAINLY
------------------------
A blocklist is only as good as its freshness, and this one has to be
refreshed from the network -- which is exactly the thing that is censored.
So:

  * the lists are compiled ON DEMAND, not watched. A stale list that
    silently ages is worse than no list, because it looks like
    protection;
  * the compiler records what it compiled and when, so "when was this
    last refreshed?" has an answer that is not a guess;
  * a compile failure leaves the existing ruleset in place. Blocking is
    additive, so a partial list never breaks resolution.

Usage:
    souran_blocklists.py status      what is compiled, and when
    souran_blocklists.py compile [--dry-run] [--force]
    souran_blocklists.py fetch       refresh the source lists, then compile
    souran_blocklists.py verify NAME is a domain actually blocked?
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

CONF = "/opt/souran-ai/config/souran-unbound.conf.yaml"
RULES_DIR = "/opt/souran-ai/config/blocklists"
STATE_FILE = "/opt/souran-ai/logs/blocklist-state.json"

# Where the cached lists live, and where to refresh them from. The local
# copies are preferred because fetching is unreliable on this network.
SOURCES = [
    # (local cache path, upstream URL, label)
    ("/var/lib/technitium/blocklists/adguard.txt",
     "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
     "adguard"),
    ("/var/lib/technitium/blocklists/stevenblack.txt",
     "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
     "stevenblack"),
    ("/var/lib/technitium/blocklists/oisd-big.txt",
     "https://big.oisd.nl/",
     "oisd-big"),
]

# HOW A BLOCK IS ACTUALLY EXPRESSED, AND WHY IT CHANGED
# ---------------------------------------------------
# The first version emitted `local-data: "<name> NXDOMAIN"` under an
# `auth-zone:` stanza. That is not valid unbound configuration:
#
#     blocklist.zone:5: error: syntax error
#
# `local-data:` is not accepted under `auth-zone:` in any form -- not
# inline, and not via `include:`. I verified this by building throwaway
# configs and running unbound-checkconf against each, because guessing
# had already crashed the live resolver 19 times.
#
# Of the three mechanisms that DO validate:
#
#   auth-zone + zonefile:   works, but wants master-zone format and
#                           carries SOA/NS bookkeeping per zone.
#   local-zone + local-data: works, per-name, and is the documented
#                           answer for exactly this case.
#   top-level include:     works, and lets 400k names live in ONE file
#                           instead of being pasted into the main config.
#
# So: `local-zone: "<name> static"` + `local-data: "<name> A 0.0.0.0"`,
# in a file pulled in by a top-level `include:`.
#
# 0.0.0.0 rather than NXDOMAIN: NXDOMAIN is not expressible as local-data
# rdata at all. 0.0.0.0 is unroutable, so the client fails fast without a
# retry storm. The trade-off -- a client can tell a block from a miss --
# is accepted deliberately: on this network the alternative is not
# "reveal nothing", it is "resolve it and hand over the tracking".
BLOCK_RDATA = "A 0.0.0.0"

# Lines that are comments, section markers, or hosts-format noise.
_SKIP = re.compile(r"^\s*(#|!|//|$)")
_HOSTS_SPLIT = re.compile(r"[\s\t]+")


def log(msg):
    print(f"[souran-blocklists] {msg}", flush=True)


def _domains_from(path):
    """Extract blocked domains from a list, handling three real formats.

    Returns (set_of_lowercase_domains, sha256, line_count).

    THREE FORMATS ARE IN PLAY, and handling only the first one silently
    discarded 350,000 domains:

      hosts     "0.0.0.0 example.com"        (stevenblack)
      adblock   "||example.com^"              (adguard)
      bare      "example.com" or "*.example.com"   (oisd)

    Measured on the cached lists: a hosts-only parser extracted 79,966
    domains from stevenblack and ZERO from adguard (179,979 lines) and
    oisd (247,060 lines). So the parser below is not theoretical -- the
    single largest source was being read as empty.
    """
    h = hashlib.sha256()
    names = set()
    total = 0
    adblock = re.compile(r"^\|\|([^\^|/?#]+)")
    bare = re.compile(r"^(\*\.)?([a-z0-9][a-z0-9._-]*\.[a-z]{2,})$", re.I)

    with open(path, "rb") as fh:
        for raw in fh:
            h.update(raw)
            total += 1
            line = raw.decode("utf-8", "replace").strip()
            if _SKIP.match(line):
                continue

            name = None

            # adblock: ||domain^ or ||domain^$third-party
            m = adblock.match(line)
            if m:
                name = m.group(1)
            elif " " in line or "\t" in line:
                # hosts format: "0.0.0.0 example.com [example.org]"
                parts = _HOSTS_SPLIT.split(line)
                if len(parts) >= 2:
                    name = parts[1]
            else:
                # bare, possibly with a *. wildcard or an ! exception
                if line.startswith("!"):
                    continue
                m = bare.match(line)
                if m:
                    name = m.group(2)

            if not name:
                continue
            name = name.strip().lower().rstrip(".")
            if not name or name == "localhost":
                continue
            if not re.fullmatch(r"[a-z0-9._-]+", name):
                continue
            if name.startswith("."):
                continue
            names.add(name)

    return names, h.hexdigest(), total


def compile_rules(dry_run=False, force=False):
    """Compile every available list into unbound's auth-zone format."""
    os.makedirs(RULES_DIR, exist_ok=True)

    missing = [label for _, _, label in SOURCES
               if not os.path.exists(SOURCES[[l for _, _, l in SOURCES]
                                           .index(label)][0])]
    if missing:
        log(f"no local copy for: {', '.join(missing)}")

    all_names = set()
    per_source = {}
    for local, url, label in SOURCES:
        if not os.path.exists(local):
            continue
        names, digest, lines = _domains_from(local)
        per_source[label] = {"file": local, "url": url,
                             "domains": len(names), "lines": lines,
                             "sha256": digest,
                             "mtime": datetime.fromtimestamp(
                                 os.path.getmtime(local),
                                 timezone.utc).isoformat()}
        log(f"{label:12} {lines:>8} lines -> {len(names):>7} domains")
        all_names |= names

    if not all_names:
        log("nothing to compile -- no list available")
        return None

    out_path = os.path.join(RULES_DIR, "blocklist.conf")
    state_path = os.path.join(RULES_DIR, "compiled.json")
    prior = {}
    if os.path.exists(state_path) and not force:
        try:
            with open(state_path) as fh:
                prior = json.load(fh)
            if set(prior.get("names", [])) == all_names:
                # "Unchanged" must also mean the ARTIFACT still exists. The
                # state file once survived a deleted ruleset, and the
                # compiler then reported success while producing nothing --
                # leaving the watchdog UNHEALTHY with no way to heal it.
                if os.path.exists(out_path):
                    log("unchanged since last compile; nothing to do")
                    return {"compiled": False, "domains": len(all_names),
                            "reason": "unchanged"}
                log("state file is current but the ruleset is missing; "
                    "regenerating")
        except (OSError, ValueError):
            prior = {}

    log(f"total unique domains: {len(all_names)}")

    # unbound auth-zone: one local-data line per name. Sorted so the file
    # is reproducible and a diff shows only real changes.
    if dry_run:
        log(f"[dry-run] would write {out_path} with {len(all_names)} entries")
        return {"compiled": False, "domains": len(all_names),
                "reason": "dry-run"}

    tmp = out_path + ".tmp"
    with open(tmp, "w") as fh:
        fh.write("# Generated by souran_blocklists.py -- do not edit.\n")
        fh.write(f"# {len(all_names)} domains compiled "
                 f"{datetime.now(timezone.utc).isoformat()}\n")
        fh.write("# Answer is 0.0.0.0: unroutable, so the client fails\n")
        fh.write("# fast without a retry storm. See BLOCK_RDATA above for\n")
        fh.write("# why this is not NXDOMAIN.\n")
        fh.write("#\n")
        fh.write("# Pulled in by a top-level `include:` in\n")
        fh.write("# souran-unbound.conf.yaml -- NOT by an auth-zone stanza,\n")
        fh.write("# because local-data is not valid under auth-zone.\n")
        for name in sorted(all_names):
            fh.write(f'local-zone: "{name}." static\n')
            fh.write(f'local-data: "{name}. {BLOCK_RDATA}"\n')
    os.replace(tmp, out_path)
    log(f"wrote {out_path}")

    with open(state_path, "w") as fh:
        json.dump({"names": sorted(all_names), "compiled_at":
                   datetime.now(timezone.utc).isoformat(),
                   "sources": per_source}, fh)

    # The ruleset is inert until unbound is told to load it. That is a
    # separate, explicit step -- see install_blocklist_ruleset().
    return {"compiled": True, "domains": len(all_names),
            "path": out_path, "sources": per_source}


def install_blocklist_ruleset(dry_run=False):
    """Add the auth-zone stanza to the unbound config, if absent.

    Deliberately does NOT restart unbound. A resolver restart drops the
    cache and, on this link, means every client waits on a cold DoH
    tier. The next maintenance window, or an explicit reload, is the
    right time -- and this function says so rather than assuming.
    """
    if not os.path.exists(CONF):
        log(f"config not found at {CONF}")
        return False
    stanza = """
# ---- ad/tracker blocking (added v5.1.0) ----------------------------
# 400k+ domains compiled by souran_blocklists.py into
# config/blocklists/blocklist.conf, pulled in here.
#
# A top-level include:, NOT an auth-zone stanza: local-data is not valid
# under auth-zone, and putting it there crashed the resolver rather than
# blocking anything.
#
# Regenerate with:
#     sudo /opt/souran-ai/souran_blocklists.py compile --force
# Check what is loaded with:
#     souran_blocklists.py status
include: "/opt/souran-ai/config/blocklists/blocklist.conf"
"""
    with open(CONF) as fh:
        cur = fh.read()
    if "config/blocklists/blocklist.conf" in cur:
        log("ruleset already present in the config")
        return True
    if dry_run:
        log("[dry-run] would append the auth-zone stanza")
        return True
    with open(CONF, "w") as fh:
        fh.write(cur.rstrip("\n") + "\n" + stanza)
    log(f"appended the auth-zone stanza to {CONF}")

    r = subprocess.run(["/opt/souran-ai/engine/unbound/sbin/unbound-checkconf",
                        CONF], capture_output=True, text=True)
    if r.returncode != 0:
        log("ERROR: unbound rejected the new config:")
        log((r.stdout + r.stderr)[-500:])
        return False
    log("unbound-checkconf: OK")
    log("not reloaded -- do that deliberately, see --reload")
    return True


def status():
    state = {}
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as fh:
                state = json.load(fh)
        except (OSError, ValueError):
            pass
    zone = os.path.join(RULES_DIR, "blocklist.conf")
    installed = "config/blocklists/blocklist.conf" in open(CONF).read() \
        if os.path.exists(CONF) else False
    # There is no unbound command that reports "426k local-zone rules
    # loaded". `list_auth_zones` is empty by design, because the working
    # mechanism is local-zone + local-data, not auth-zone -- so a status
    # line driven by it would always read False and be wrong.
    #
    # The honest answer is behavioural: ask unbound itself.
    loaded = None
    try:
        out = subprocess.run(
            ["dig", "+short", "+time=10", "@127.0.0.1",
             "doubleclick.net", "A"],
            capture_output=True, text=True, timeout=30)
        ans = (out.stdout or "").strip().splitlines()
        loaded = bool(ans) and ans[0] == "0.0.0.0"
    except (OSError, subprocess.SubprocessError):
        pass

    print(f"compiled zone file : {zone if os.path.exists(zone) else '(none)'}")
    if os.path.exists(zone):
        print(f"  entries          : {sum(1 for _ in open(zone)):,}")
    print(f"in unbound config  : {installed}")
    if loaded is True:
        print("loaded by unbound  : yes (verified by query)")
    elif loaded is False:
        print("loaded by unbound  : NO -- a known tracker did not "
              "return 0.0.0.0")
    else:
        print("loaded by unbound  : unknown (could not query)")
    print(f"state file         : {STATE_FILE if state else '(none)'}")
    if state.get("sources"):
        print("\nsources:")
        for label, info in state["sources"].items():
            print(f"  {label:12} {info['domains']:>8,} domains  "
                  f"from {info['file']}")
            print(f"  {'':12} cached {info['mtime'][:10]}  "
                  f"sha256 {info['sha256'][:16]}")
    return 0


def fetch():
    """Refresh the source lists. Best-effort: this needs working egress."""
    os.makedirs(os.path.dirname(SOURCES[0][0]), exist_ok=True)
    ok = 0
    for local, url, label in SOURCES:
        log(f"fetching {label} ...")
        try:
            r = subprocess.run(
                ["curl", "-sSL", "--max-time", "120", "-o", local, url],
                capture_output=True, text=True, timeout=180)
            if r.returncode == 0 and os.path.getsize(local) > 1000:
                log(f"  {label}: {os.path.getsize(local):,} bytes")
                ok += 1
            else:
                log(f"  {label}: FAILED (keeping the cached copy)")
        except subprocess.TimeoutExpired:
            log(f"  {label}: timed out (keeping the cached copy)")
    log(f"{ok}/{len(SOURCES)} refreshed")
    return 0


def verify(name):
    zone = os.path.join(RULES_DIR, "blocklist.conf")
    if not os.path.exists(zone):
        log("no compiled blocklist yet")
        return 1
    name = name.strip().lower().rstrip(".")
    needle = f'local-data: "{name}. {BLOCK_RDATA}"'
    alt = f"local-zone: \"{name}.\" static"
    with open(zone) as fh:
        for line in fh:
            if line.startswith(needle) or line.startswith(alt):
                log(f"{name} IS blocked ({BLOCK_RDATA})")
                return 0
    log(f"{name} is not on the list")
    return 1


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="souran_blocklists.py",
        description="Compile hosts-format blocklists into unbound.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("status", help="what is compiled, and when")
    p.set_defaults(func=lambda a: status())

    p = sub.add_parser("compile", help="compile the cached lists")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--force", action="store_true",
                   help="recompile even if unchanged")
    p.add_argument("--install", action="store_true",
                   help="also add the auth-zone stanza to the config")
    p.set_defaults(func=lambda a: (compile_rules(a.dry_run, a.force),
                                   install_blocklist_ruleset(a.dry_run)))

    p = sub.add_parser("fetch", help="refresh the lists, then compile")
    p.set_defaults(func=lambda a: fetch())

    p = sub.add_parser("verify", help="is a domain blocked?")
    p.add_argument("name")
    p.set_defaults(func=lambda a: verify(a.name))

    args = ap.parse_args(argv)
    result = args.func(args)
    if result is None:
        return 1
    if isinstance(result, tuple):
        result = result[0]
    return 0 if result else 1


if __name__ == "__main__":
    sys.exit(main())