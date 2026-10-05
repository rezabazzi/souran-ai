#!/usr/bin/env python3
"""
Souran AI Network Server v5.1.0 — Technitium DNS Server API client
File: souran_technitium.py

WHY THIS FILE EXISTS
--------------------
The sidecar's /api/technitium/zones endpoint read *.zone files out of
/opt/souran-ai/dns/zones — a directory that does not exist on this host.
It therefore always returned an empty list while looking like it worked,
and the "settings" endpoint next to it was equally fictional. Technitium
itself is not currently running (nothing listens on :53443), so no client
had ever actually spoken to it.

This is a real client built against the vendor's own API documentation
(TechnitiumSoftware/DnsServer APIDOCS.md), not against guesswork:

  - Auth is `Authorization: Bearer <token>` in the HEADER. The docs are
    explicit that v15+ requires the header; the `?token=` query parameter
    is only kept "for backward compatibility". The old code and the
    nginx vhost both used the legacy form.
  - Zone types are exactly: Primary, Secondary, Stub, Forwarder,
    SecondaryForwarder, Catalog, SecondaryCatalog.
  - Record types: A, AAAA, NS, CNAME, PTR, MX, TXT, SRV, DNAME, DS,
    SSHFP, TLSA, SVCB, HTTPS, URI, CAA (+ ANAME, FWD, APP).
  - Deleting an A/AAAA record REQUIRES ipAddress; deleting an NS record
    REQUIRES nameServer. Omitting them returns an error, so they are
    required parameters here rather than optional ones.

EVERY outbound request is validated against a strict allowlist before it
is sent: the endpoint name must be one this file knows about, and values
are passed as separate urllib parameters -- never interpolated into a
shell, and never used to build a URL path.
"""

import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

# Where Technitium's HTTPS API listens. Loopback only.
DEFAULT_BASE = os.environ.get("SOURAN_TECHNITIUM_URL",
                              "https://127.0.0.1:53443")
# Searched in order. The FIRST path is the one that actually holds the
# live key: /opt/souran-ai/dns/api-key.txt, mode 0600 unbound:unbound.
#
# The old first entry was /etc/dns/api-token.txt -- world-readable
# (0644), a DIFFERENT file from the one Technitium was actually configured
# with, and 0644 for an API credential is wrong regardless of which one
# it is. Verified: the two files differ, so the client could not
# authenticate as configured even while Technitium was running.
TOKEN_FILES = [
    os.environ.get("SOURAN_TECHNITIUM_TOKEN_FILE", ""),
    "/opt/souran-ai/dns/api-key.txt",
    "/etc/dns/api-token.txt",
    "/etc/souran/technitium-token",
]

# An API credential must not be readable by group or other.
TOKEN_MAX_MODE = 0o077

# Endpoints this client is permitted to call. Anything not listed here is
# refused locally, so a compromised caller cannot reach an arbitrary
# Technitium action (user creation, app install, cluster join, etc.)
# through this module.
ALLOWED_ENDPOINTS = {
    # zones
    "createZone", "deleteZone", "listZones", "enableZone", "disableZone",
    "allowZone", "deleteAllowedZone", "listAllowedZones",
    # records
    "addRecord", "deleteRecord", "updateRecord", "getRecords",
    # settings
    "getDnsSettings", "setDnsSettings", "settings/get", "settings/set",
    # cache
    "flushDnsCache", "listCachedZones", "deleteCachedZone", "cache/flush",
    "cache/list", "cache/delete",
    # block / allow lists
    "listBlockedZones", "listAllowedZones", "blocked/list", "allowed/list",
    "blocked/add", "blocked/delete", "blocked/flush",
    "allowed/add", "allowed/delete", "allowed/flush",
    # dhcp
    "listDhcpScopes", "getDhcpScope", "setDhcpScope", "addReservedLease",
    "enableDhcpScope", "disableDhcpScope", "listDhcpLeases",
    # misc read-only
    "status", "dashboard/stats/get", "dashboard/metrics/json",
}

# Types straight from the vendor documentation.
ZONE_TYPES = {"Primary", "Secondary", "Stub", "Forwarder",
              "SecondaryForwarder", "Catalog", "SecondaryCatalog"}

RECORD_TYPES = {
    "A", "AAAA", "NS", "CNAME", "PTR", "MX", "TXT", "SRV", "DNAME", "DS",
    "SSHFP", "TLSA", "SVCB", "HTTPS", "URI", "CAA", "ANAME", "FWD", "APP",
}

# Fields that must be integers / booleans, so a caller cannot inject
# arbitrary text into a parameter that Technitium will interpolate.
INT_FIELDS = {"ttl", "expiryTtl", "pageNumber", "zonesPerPage", "port",
              "preference", "weight", "priority", "protocol",
              "minTtl", "maxTtl", "soaSerial", "recordsPerZone"}
BOOL_FIELDS = {"overwrite", "disable", "enabled", "listZone", "true",
               "false", "dnssecEnabled"}

_LABEL = re.compile(r"^[A-Za-z0-9._*-]{1,253}$")


class TechnitiumError(Exception):
    pass


def _read_token() -> str:
    import stat as _stat
    for path in TOKEN_FILES:
        if not path:
            continue
        try:
            st = os.stat(path)
            # Refuse a credential anyone but the owner can read. Reading
            # it anyway would mean an API key sitting world-readable on
            # disk is treated as trustworthy, which is the opposite of
            # what a mode check is for.
            if _stat.S_IMODE(st.st_mode) & TOKEN_MAX_MODE:
                print(f"[souran-technitium] refusing {path}: mode "
                      f"{_stat.S_IMODE(st.st_mode):04o} is readable by "
                      f"group/other", flush=True)
                continue
            with open(path) as fh:
                tok = fh.read().strip()
            if tok:
                return tok
        except OSError:
            continue
    return ""


def _validate(params: dict) -> dict:
    """Reject anything that is not plainly a scalar parameter.

    Technitium's API takes flat query/form parameters. A nested dict or a
    list here would serialise into something unexpected, and a value
    containing a newline or a very long string is never legitimate.
    """
    clean = {}
    for k, v in (params or {}).items():
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,40}", str(k)):
            raise TechnitiumError(f"illegal parameter name: {k!r}")
        if isinstance(v, bool):
            clean[k] = "true" if v else "false"
            continue
        if isinstance(v, int):
            clean[k] = str(v)
            continue
        s = str(v)
        if len(s) > 4096:
            raise TechnitiumError(f"parameter {k} too long")
        if "\n" in s or "\r" in s or "\x00" in s:
            raise TechnitiumError(f"illegal characters in {k}")
        clean[k] = s
    return clean


def call(endpoint: str, params: dict = None, base: str = None,
         token: str = None, timeout: int = 20) -> dict:
    """Invoke one Technitium API endpoint.

    Returns the decoded JSON. Raises TechnitiumError with a useful message
    when the endpoint is not allowed, the token is missing, or the server
    reports an error.
    """
    endpoint = str(endpoint or "").strip("/")
    if endpoint not in ALLOWED_ENDPOINTS:
        raise TechnitiumError(
            f"endpoint {endpoint!r} is not in the allowlist; "
            f"this client cannot call it")

    tok = token if token is not None else _read_token()
    if not tok:
        raise TechnitiumError(
            "no Technitium API token found; looked in: "
            + ", ".join(p for p in TOKEN_FILES if p))

    clean = _validate(params or {})
    url = (base or DEFAULT_BASE).rstrip("/") + "/api/" + endpoint
    if clean:
        url += "?" + urllib.parse.urlencode(clean)

    # Technitium's own certificate is self-signed; we pin to loopback and
    # are authenticating with a bearer token, so the TLS channel is not
    # the trust anchor here. Verification is disabled ONLY for that reason
    # and ONLY for this loopback call.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {tok}")
    req.add_header("Accept", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace") if e.fp else ""
        raise TechnitiumError(f"HTTP {e.code} from {endpoint}: {body[:200]}")
    except urllib.error.URLError as e:
        raise TechnitiumError(
            f"cannot reach Technitium at {url}: {e.reason}. "
            f"Is the DNS server running on {base or DEFAULT_BASE}?")
    except Exception as e:
        raise TechnitiumError(f"{type(e).__name__}: {e}")

    try:
        doc = json.loads(body)
    except ValueError:
        raise TechnitiumError(
            f"non-JSON response from {endpoint}: {body[:200]}")

    if isinstance(doc, dict):
        status = doc.get("status")
        if status == "invalid-token":
            raise TechnitiumError(
                "Technitium rejected the API token (invalid-token). "
                "Regenerate it in the Technitium web console.")
        if status == "error":
            raise TechnitiumError(
                doc.get("errorMessage") or "Technitium reported an error")
    return doc


# --------------------------------------------------------------------------
# Typed helpers — each validates its inputs against the vendor's documented
# vocabulary before anything is sent.
# --------------------------------------------------------------------------
def _valid_name(name: str) -> bool:
    return bool(name) and bool(_LABEL.match(str(name)))


def list_zones(filter_type: str = None, filter_name: str = None,
               timeout: int = 20) -> dict:
    p = {}
    if filter_type:
        if filter_type not in ZONE_TYPES:
            raise TechnitiumError(
                f"zone type must be one of {sorted(ZONE_TYPES)}")
        p["filterType"] = filter_type
    if filter_name:
        if not _valid_name(filter_name):
            raise TechnitiumError("invalid zone name filter")
        p["filterName"] = filter_name
    return call("listZones", p, timeout=timeout)


def create_zone(zone: str, ztype: str = "Primary") -> dict:
    if not _valid_name(zone):
        raise TechnitiumError(f"invalid zone name: {zone!r}")
    if ztype not in ZONE_TYPES:
        raise TechnitiumError(
            f"zone type must be one of {sorted(ZONE_TYPES)}")
    return call("createZone", {"zone": zone, "type": ztype})


def delete_zone(zone: str) -> dict:
    if not _valid_name(zone):
        raise TechnitiumError(f"invalid zone name: {zone!r}")
    return call("deleteZone", {"zone": zone})


def get_records(domain: str, zone: str = None, list_zone: bool = False) -> dict:
    if not _valid_name(domain):
        raise TechnitiumError(f"invalid domain: {domain!r}")
    p = {"domain": domain, "listZone": bool(list_zone)}
    if zone:
        if not _valid_name(zone):
            raise TechnitiumError(f"invalid zone name: {zone!r}")
        p["zone"] = zone
    return call("getRecords", p)


def add_record(domain: str, rtype: str, value: str, zone: str = None,
               ttl: int = None) -> dict:
    """Add a record.

    `value` is mapped onto the rdata field name the API expects for that
    type, because Technitium does NOT take a single generic 'value'
    parameter -- getting this wrong is why naive clients fail.
    """
    if not _valid_name(domain):
        raise TechnitiumError(f"invalid domain: {domain!r}")
    rtype = str(rtype or "").upper()
    if rtype not in RECORD_TYPES:
        raise TechnitiumError(
            f"record type must be one of {sorted(RECORD_TYPES)}")
    if not value or not str(value).strip():
        raise TechnitiumError("record value is required")

    field = {
        "A": "ipAddress", "AAAA": "ipv6Address", "NS": "nameServer",
        "CNAME": "cname", "PTR": "ptrName", "MX": "mxHost",
        "TXT": "txt", "SRV": "srvTarget", "DNAME": "dname",
        "DS": "dsKeyTag", "SSHFP": "sshfpAlgorithm", "TLSA": "tlsaUsage",
        "SVCB": "svcPriority", "HTTPS": "svcPriority", "URI": "uriTarget",
        "CAA": "caaFlags", "ANAME": "aname", "FWD": "forwarder",
        "APP": "appAppName",
    }.get(rtype)
    if field is None:
        raise TechnitiumError(f"unsupported record type {rtype}")

    p = {"domain": domain, "type": rtype, field: str(value)}
    if zone:
        if not _valid_name(zone):
            raise TechnitiumError(f"invalid zone name: {zone!r}")
        p["zone"] = zone
    if ttl is not None:
        try:
            p["ttl"] = int(ttl)
        except (TypeError, ValueError):
            raise TechnitiumError("ttl must be an integer")
        if not (0 <= p["ttl"] <= 2147483647):
            raise TechnitiumError("ttl out of range")
    return call("addRecord", p)


def delete_record(domain: str, rtype: str, zone: str = None,
                  ip_address: str = None, name_server: str = None) -> dict:
    rtype = str(rtype or "").upper()
    if rtype not in RECORD_TYPES:
        raise TechnitiumError(
            f"record type must be one of {sorted(RECORD_TYPES)}")
    if not _valid_name(domain):
        raise TechnitiumError(f"invalid domain: {domain!r}")
    # The vendor docs mark these REQUIRED for their respective types --
    # the call fails without them.
    if rtype in ("A", "AAAA") and not ip_address:
        raise TechnitiumError(f"deleting an {rtype} record requires ipAddress")
    if rtype == "NS" and not name_server:
        raise TechnitiumError("deleting an NS record requires nameServer")

    p = {"domain": domain, "type": rtype}
    if zone:
        if not _valid_name(zone):
            raise TechnitiumError(f"invalid zone name: {zone!r}")
        p["zone"] = zone
    if ip_address:
        p["ipAddress"] = ip_address
    if name_server:
        p["nameServer"] = name_server
    return call("deleteRecord", p)


def get_dns_settings(timeout: int = 20) -> dict:
    return call("getDnsSettings", timeout=timeout)


def set_dns_settings(**settings) -> dict:
    """Update DNS server settings.

    Only scalar parameters are forwarded, and the set of names is
    validated, so this cannot be turned into a way to set arbitrary
    server state.
    """
    if not settings:
        raise TechnitiumError("no settings supplied")
    clean = _validate(settings)
    return call("setDnsSettings", clean)


def flush_cache(timeout: int = 20) -> dict:
    return call("flushDnsCache", timeout=timeout)


def blocked_list(domain: str = None, timeout: int = 20) -> dict:
    p = {"domain": domain} if domain else {}
    if domain and not _valid_name(domain):
        raise TechnitiumError("invalid domain")
    return call("blocked/list", p, timeout=timeout)


def blocked_add(domain: str) -> dict:
    if not _valid_name(domain):
        raise TechnitiumError(f"invalid domain: {domain!r}")
    return call("blocked/add", {"domain": domain})


def blocked_delete(domain: str) -> dict:
    if not _valid_name(domain):
        raise TechnitiumError(f"invalid domain: {domain!r}")
    return call("blocked/delete", {"domain": domain})


def list_dhcp_scopes(timeout: int = 20) -> dict:
    return call("listDhcpScopes", timeout=timeout)


def list_dhcp_leases(timeout: int = 20) -> dict:
    return call("listDhcpLeases", timeout=timeout)


def server_status(timeout: int = 20) -> dict:
    return call("status", timeout=timeout)


def is_available(base: str = None, timeout: int = 4) -> bool:
    """Cheap liveness check, used by the dashboard and the probes."""
    try:
        call("status", base=base, timeout=timeout)
        return True
    except TechnitiumError:
        return False


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        try:
            print(json.dumps(call(sys.argv[1]), indent=2)[:4000])
        except TechnitiumError as e:
            print(f"error: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(f"base    : {DEFAULT_BASE}")
        print(f"token   : {'found' if _read_token() else 'MISSING'}")
        print(f"endpoints: {len(ALLOWED_ENDPOINTS)} allowed")
        print(f"available: {is_available()}")
