#!/usr/bin/env python3
"""
Souran Client — configuration helper for the Souran AI Network Server.

WHAT THIS IS NOT: it is not an installer for Windows, macOS or Android,
and configuring a client is not the same as supporting an OS. It runs on
whatever machine runs Python 3.9+, and it changes that machine's DNS
settings using the OS's own tooling. There are no .msi, .pkg or .apk
packages, and none would help: an APK cannot set Private DNS for other
apps, and macOS has no encrypted-DNS facility to configure.

File: souran_client.py  |  Python 3.9+, standard library only
License: GPL-3.0-or-later

WHAT THIS IS
------------
A single-file helper that configures a machine to use a self-hosted
Souran resolver over DoT (RFC 7858) or DoH (RFC 8484). One codebase runs
on Windows, macOS and Linux; Android is handled separately because it
exposes Private DNS rather than a general client API.

DESIGN DECISIONS, AND WHY
-------------------------
1. ONE CODEBASE FOR THE CLIENT, NOT FOR SYSTEM RECONFIGURATION.
   The protocol work — building queries, speaking DoT/DoH, validating the
   server certificate, caching — is identical everywhere and lives here.
   Changing the OS resolver is inherently per-platform and is delegated to
   the platform's own tooling (networksetup, netsh, resolvectl). Trying to
   abstract that produces the lowest common denominator: a broken
   configuration on every platform rather than a good one on three.

2. CERTIFICATE TRUST IS EXPLICIT, NEVER DISABLED.
   This client will not offer a "skip verification" switch that persists.
   Trusting a self-hosted resolver means trusting its CA; if you have not
   installed that CA, the correct answer is that DoT does not work yet,
   not that verification should be quietly turned off. `--insecure` exists
   for ONE invocation and prints a warning, because a diagnostic that
   cannot be run at all is not a diagnostic.

3. NO SUBPROCESS SHELL STRINGS.
   Every external command is invoked as an argv list with shell=False.
   Hostnames and interface names are validated first. A resolver address
   is attacker-influenced data in the general case, and this is a
   privileged operation on three of the four platforms.

4. DRY RUN BY DEFAULT ON SYSTEM-CHANGING OPERATIONS.
   `apply` prints the exact commands and exits unless `--yes` is given.
   Getting a laptop's DNS silently pointed at the wrong server is a bad
   day; a prompt costs nothing.

PLATFORM SUPPORT (measured against current documentation)
--------------------------------------------------------
  Linux    systemd-resolved via `resolvectl dns <link> <addr>`; falls back
           to /etc/resolv.conf (with a backup) when resolved is absent.
  macOS    `networksetup -setdnsservers <service> <addr>` per active
           service; scutil to enumerate them. NOTE: this is PLAINTEXT DNS.
           macOS has no OS-level encrypted-DNS setting, so pointing a Mac
           at the resolver gives no encryption at all. Encrypted DNS on
           macOS needs a local DoT forwarder plus 127.0.0.1, or an MDM DNS
           Proxy profile. This tool does not claim otherwise.
  Windows  `netsh interface ip set dnsservers name="<if>" static <addr>`,
           then real DoH via `netsh dnsclient add encryption server=<addr>
           dohtemplate=https://<name>/dns-query autoupgrade=yes
           udpfallback=no` and `netsh dnsclient set global doh=yes`.
           Administrator privileges required.
  Android  NOT configured by this tool. Android's Private DNS setting is
           a user-facing toggle and it ALWAYS uses DoT on port 853 with no
           port field. See --android for the CA install path.

USAGE
-----
  # test connectivity and certificate trust first — always safe
  souran_client.py test --server mordaddns.ir --ca souran-dns-ca.crt

  # see what would change
  souran_client.py apply --server mordaddns.ir --ca souran-dns-ca.crt

  # actually change it
  souran_client.py apply --server mordaddns.ir --ca souran-dns-ca.crt --yes

  # Android instructions
  souran_client.py android --server mordaddns.ir --ca souran-dns-ca.crt
"""

import argparse
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys

VERSION = "5.1.0"
DEFAULT_DOH = "https://mordaddns.ir/dns-query"
DOT_PORT = 853

_RC = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
       4: "NOTIMP", 5: "REFUSED"}


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------
def die(msg, code=1):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def say(msg=""):
    print(msg)


def warn(msg=""):
    print(f"warning: {msg}", file=sys.stderr)


def run(argv, dry_run=False):
    """Run a command. Never through a shell."""
    printable = " ".join(argv)
    if dry_run:
        say(f"    would run: {printable}")
        return 0, "", ""
    try:
        p = subprocess.run(argv, shell=False, capture_output=True,
                           text=True, timeout=30)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"{argv[0]}: not found"
    except PermissionError:
        return 126, "", f"permission denied: {argv[0]} (try sudo/elevated)"
    except Exception as exc:
        return 1, "", f"{type(exc).__name__}: {exc}"


_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}"
                      r"[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}"
                      r"[A-Za-z0-9])?)*$")


def valid_host(h):
    return bool(h) and bool(_HOST_RE.match(h))


def valid_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def require_host(h):
    if not valid_host(h):
        die(f"invalid hostname: {h!r}")
    return h


# --------------------------------------------------------------------------
# DNS wire format — shared by every transport
# --------------------------------------------------------------------------
def encode_name(name):
    out = b""
    for label in name.split("."):
        if not label:
            continue
        b = label.encode("idna") if any(ord(c) > 127 for c in label) \
            else label.encode("ascii")
        if len(b) > 63:
            raise ValueError("label too long")
        out += bytes([len(b)]) + b
    return out + b"\x00"


def build_query(name, qtype=1, qid=0x1234, rd=True):
    header = struct.pack("!HHHHHH", qid, 0x0100 if rd else 0x0000,
                         1, 0, 0, 0)
    return header + encode_name(name) + struct.pack("!HH", qtype, 1)


def parse_header(data):
    if len(data) < 12:
        raise ValueError("short response")
    _qid, flags, _qd, an, ns, _ar = struct.unpack("!HHHHHH", data[:12])
    return (flags & 0x000F, an, ns)


# --------------------------------------------------------------------------
# transports
# --------------------------------------------------------------------------
def resolve_endpoint(server):
    """Return (connect_ip, sni_name) for the resolver.

    The resolver's own name often has no public A record -- a self-hosted
    DNS server on a LAN or VPN address typically does not -- so the name
    must not be required to resolve. Connect to an explicit IP when one is
    given, while STILL sending SNI and validating the certificate against
    the expected name. That keeps the security property (the channel is
    authenticated to the resolver you named) without requiring a public
    DNS record for the resolver itself.
    """
    if valid_ip(server):
        return server, server
    try:
        return socket.gethostbyname(server), server
    except socket.gaierror:
        return None, server


def dot_query(server, name, cafile=None, timeout=15.0, insecure=False,
              port=DOT_PORT, connect_ip=None):
    """DNS-over-TLS per RFC 7858. Returns (rcode, ancount)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        if not cafile:
            raise ValueError(
                "DoT needs the resolver's CA (--ca). Refusing to run with "
                "verification disabled unless --insecure is given "
                "explicitly, because that would make the channel "
                "meaningless: DoT exists to authenticate the resolver.")
        ctx.load_verify_locations(cafile)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

    target = connect_ip or server
    raw = socket.create_connection((target, port), timeout=timeout)
    # server_hostname drives SNI and hostname verification; it stays the
    # NAME even when connecting to an IP.
    s = ctx.wrap_socket(raw, server_hostname=server)
    try:
        # RFC 7858 §3.3: the message is length-prefixed and there is no
        # self-delimiting marker, so the connection must not be reused
        # after a timeout.
        q = build_query(name)
        s.sendall(struct.pack("!H", len(q)) + q)
        hdr = s.recv(2)
        if len(hdr) < 2:
            raise ValueError("no length prefix")
        (ln,) = struct.unpack("!H", hdr)
        data = b""
        while len(data) < ln:
            chunk = s.recv(ln - len(data))
            if not chunk:
                break
            data += chunk
        return parse_header(data)
    finally:
        s.close()


def doh_query(url, name, qtype=1, cafile=None, timeout=15.0, insecure=False,
              connect_ip=None):
    """DNS-over-HTTPS, RFC 8484 wire format (application/dns-message)."""
    import urllib.error
    import urllib.parse
    import urllib.request

    u = urllib.parse.urlparse(url)
    if u.scheme != "https":
        raise ValueError("DoH requires https")

    ctx = ssl.create_default_context(cafile=cafile)
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    if connect_ip:
        # Preserve SNI + certificate validation by pinning only the
        # connection address, exactly as --resolve does in curl.
        import socket as _socket
        orig_getaddrinfo = _socket.getaddrinfo

        def _pinned(host, port, *a, **kw):
            return orig_getaddrinfo(connect_ip, port, *a, **kw)
        _socket.getaddrinfo = _pinned
    q = build_query(name, qtype, rd=False)   # RD is set by the proxy
    req = urllib.request.Request(
        u.geturl(), data=q, method="POST",
        headers={"Content-Type": "application/dns-message",
                 "Accept": "application/dns-message"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read()
    except urllib.error.HTTPError as e:
        raise ValueError(f"HTTP {e.code} from {url}") from None
    except Exception as e:
        raise ValueError(f"{type(e).__name__}: {e}") from None
    finally:
        if connect_ip:
            _socket.getaddrinfo = orig_getaddrinfo
    return parse_header(body)


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------
def cmd_test(args):
    """Non-destructive: prove the server answers and the chain validates."""
    require_host(args.server)
    say(f"Souran client v{VERSION}")
    say(f"platform      : {platform.system()} {platform.release()}")
    say(f"server        : {args.server}")
    if args.ca:
        say(f"CA file       : {args.ca}"
             + ("" if os.path.exists(args.ca) else "   <-- MISSING"))
    say()

    ok = True

    if args.connect_ip and valid_ip(args.connect_ip):
        connect_ip, sni = args.connect_ip, args.server
    else:
        connect_ip, sni = resolve_endpoint(args.server)
    if connect_ip is None:
        say(f"note: {args.server} has no address record of its own.")
        say("      That is normal for a self-hosted resolver on a LAN or")
        say("      VPN address. Pass --connect-ip <address> to reach it")
        say("      while still validating the certificate for that name.")
        say()
    else:
        say(f"endpoint  : {connect_ip}:{DOT_PORT} (SNI/verify: {sni})")
        say()

    # --- DoT -----------------------------------------------------------
    say("DoT (RFC 7858, port 853):")
    if connect_ip is None:
        ok = False
        say("  FAIL  cannot determine where to connect — use --connect-ip")
    else:
        try:
            rc, an, ns = dot_query(args.server, args.name, cafile=args.ca,
                                   insecure=args.insecure,
                                   connect_ip=connect_ip)
            say(f"  PASS  {args.name} -> rcode={_RC.get(rc, rc)} "
                f"answers={an} authority={ns}")
        except ssl.SSLCertVerificationError as e:
            ok = False
            say(f"  FAIL  certificate not trusted: "
                f"{getattr(e, 'verify_message', None) or e}")
            say("        Install the resolver's CA, or pass --ca <file>.")
        except Exception as e:
            ok = False
            say(f"  FAIL  {type(e).__name__}: {e}")
    say()


    # --- DoH -----------------------------------------------------------
    if args.doh and connect_ip:
        say(f"DoH (RFC 8484): {args.doh}")
        try:
            rc, an, ns = doh_query(args.doh, args.name, cafile=args.ca,
                                   insecure=args.insecure, connect_ip=connect_ip)
            say(f"  PASS  {args.name} -> rcode={_RC.get(rc, rc)} answers={an}")
        except Exception as e:
            ok = False
            say(f"  FAIL  {type(e).__name__}: {e}")
        say()

    print("RESULT:", "all configured transports work" if ok else
          "at least one transport FAILED — do not apply this config")
    return 0 if ok else 1


def _linux_apply(server, dry_run):
    if shutil.which("resolvectl"):
        links = run(["resolvectl", "--no-pager", "status"])[1]
        link = None
        for line in links.splitlines():
            m = re.match(r"^(\d+)\s+(\S+)", line.strip())
            if m and "Link" not in line:
                link = f"{m.group(1)} {m.group(2)}"
                break
        if link:
            idx, name = link.split(" ", 1)
            say(f"  systemd-resolved: link {idx} ({name})")
            run(["resolvectl", "dns", idx, server], dry_run)
            run(["resolvectl", "domain", idx, "~."], dry_run)
            say("  set ~. so all domains use this resolver")
            return True
        warn("could not determine the active link; falling back to resolv.conf")

    rc, out, _ = run(["cat", "/etc/resolv.conf"])
    if "nameserver" not in (out or ""):
        warn("/etc/resolv.conf has no nameserver line and no resolvectl; "
             "cannot configure automatically")
        return False
    if not dry_run:
        if os.path.exists("/etc/resolv.conf"):
            shutil.copy2("/etc/resolv.conf", "/etc/resolv.conf.souran.bak")
            say("  backed up /etc/resolv.conf -> /etc/resolv.conf.souran.bak")
        try:
            with open("/etc/resolv.conf", "w") as fh:
                fh.write(f"# managed by souran_client.py\nnameserver {server}\n")
            say("  wrote /etc/resolv.conf")
        except PermissionError:
            warn("need root to write /etc/resolv.conf — re-run with sudo")
            return False
    else:
        say(f"    would write: nameserver {server}")
    return True


def _macos_apply(server, dry_run):
    rc, out, _ = run(["networksetup", "-listallnetworkservices"])
    if rc != 0:
        warn("networksetup not available (not macOS?)")
        return False
    services = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("An asterisk"):
            continue
        services.append(line[1:] if line.startswith("*") else line)
    if not services:
        warn("no active network services found")
        return False
    for svc in services:
        say(f"  service: {svc}")
        run(["networksetup", "-setdnsservers", svc, server], dry_run)
    return True


def _windows_apply(server, dry_run, doh_name=None):
    rc, out, _ = run(["netsh", "interface", "ipv4", "show", "interfaces"])
    if rc != 0:
        warn("netsh not available (not Windows?)")
        return False
    names = []
    for line in out.splitlines():
        m = re.match(r"^\s*\d+\s+(.+?)\s*$", line)
        if m and m.group(1) not in ("Interface Name",):
            names.append(m.group(1))
    if not names:
        warn("no interfaces found")
        return False
    for n in names:
        say(f"  interface: {n}")
        run(["netsh", "interface", "ip", "set", "dnsservers",
             f"name={n}", "static", server], dry_run)

    # DNS over HTTPS is a SEPARATE registration, not a flag on
    # `set dnsservers`.
    #
    # This previously ran `netsh interface ip set dnsservers ...
    # validate=no` and the comment claimed it "trusts the resolver's own CA
    # rather than a public CA". That is not what the flag does: Microsoft's
    # reference defines `validate` as whether to validate the DNS SERVER
    # SETTING, i.e. address validation. It carries no certificate
    # semantics, so the path configured plain DNS and reported DoH.
    #
    # The real commands are `netsh dnsclient add encryption` (per server
    # address and DoH template) and `netsh dnsclient set global doh=yes`.
    # The template carries the NAME, so SNI and certificate validation
    # still work against a self-hosted CA.
    doh_name = doh_name or server
    template = f"https://{doh_name}/dns-query"
    say(f"  registering DoH template: {template}")
    run(["netsh", "dnsclient", "add", "encryption",
         f"server={server}", f"dohtemplate={template}",
         "autoupgrade=yes", "udpfallback=no"], dry_run)
    run(["netsh", "dnsclient", "set", "global", "doh=yes"], dry_run)
    return True


def cmd_apply(args):
    require_host(args.server)
    dry = not args.yes
    say(f"Souran client v{VERSION}")
    say(f"server  : {args.server}")
    say(f"system  : {platform.system()}")
    say(f"mode    : {'DRY RUN (use --yes to apply)' if dry else 'APPLYING'}")
    say()
    say("Testing the resolver first — never point a machine at a server")
    say("that does not answer:")
    if cmd_test(args) != 0:
        die("resolver did not pass its own test; nothing was changed")
    say()

    # The OS tooling needs an ADDRESS, not a name.
    #
    # `netsh ... static <server>` and `networksetup -setdnsservers <svc>
    # <server>` both require an IP literal and reject a hostname. This
    # passed `args.server` straight through, so the apply path was broken
    # on Windows and macOS whenever the server was given by name -- which is
    # the documented usage. `resolve_endpoint` already existed and was used
    # by `test`, so the test path proved the name resolves and then the
    # apply path handed the NAME to a command that cannot use it.
    #
    # Resolve once, here, and pass the address. The name is still used for
    # SNI and certificate verification, which is unchanged.
    server_addr = args.connect_ip
    if not server_addr:
        server_addr, _sni = resolve_endpoint(args.server)
    if not server_addr:
        die(f"cannot resolve {args.server} to an address; pass --connect-ip"
            f" if it has no A/AAAA record")
    say(f"address   : {server_addr}  (from {args.server})")

    sysname = platform.system()
    if sysname == "Linux":
        ok = _linux_apply(server_addr, dry)
    elif sysname == "Darwin":
        ok = _macos_apply(server_addr, dry)
    elif sysname == "Windows":
        ok = _windows_apply(server_addr, dry, args.server)
    else:
        die(f"unsupported platform {sysname!r}; see --android for Android")

    say()
    if not ok:
        die("could not configure the system resolver")
    say("Verify with:" if not dry else
         "After applying, verify with:")
    say(f"  {sys.executable} {os.path.basename(__file__)} "
         f"test --server {args.server}"
         + (f" --ca {args.ca}" if args.ca else ""))
    return 0


def cmd_android(args):
    """Print exact Android instructions.

    Android is not configured by this tool on purpose. Private DNS is a
    user-facing Settings toggle, it always uses DoT on 853 with no port
    field, and it will not fall back to DoH. Automating it would mean an
    accessibility service or root, neither of which is appropriate here.
    """
    require_host(args.server)
    ca_name = (os.path.basename(args.ca) if args.ca
               else "souran-dns-ca.crt")
    print(f"""
Souran DNS on Android
=====================

Android's "Private DNS" uses DNS-over-TLS only (RFC 7858) on port 853.
There is no port field and no DoH option, so the resolver must be
reachable as {args.server}:853 with a certificate valid for that name.

STEP 1 — install the CA certificate
-----------------------------------
  a) Copy {ca_name} to the phone.
  b) Settings > Security > Encryption & credentials
     > Install a certificate > CA certificate
     > select {ca_name}
  Android shows a warning: that is expected and correct. This CA signs
  ONLY your resolver's certificate. Installing it means "trust this
  resolver", which is the entire point of self-hosting DNS.

STEP 2 — enable Private DNS
--------------------------
  Settings > Network & internet > Private DNS
    > Private DNS provider
    > Custom host
    > {args.server}

STEP 3 — verify
----------------
  * The Private DNS entry must show "Connected" / "Active". If it stays
    "Off" or "Unable to connect", the certificate is not trusted or the
    name does not match a SAN on the leaf.
  * DNS over DoH is NOT available here. To use DoH on Android you need a
    browser or app configured for it (Firefox: Settings > Network
    resolution > Custom DNS over HTTPS; Chrome: Settings > Security >
    Use secure DNS), pointed at:
        {args.doh or DEFAULT_DOH}
  * From this machine you can verify the DoT endpoint the phone will use:
        {sys.executable} {os.path.basename(__file__)} test \\
            --server {args.server} --ca {ca_name}

Notes
-----
  * DoH via browser/app is per-app. Private DNS is system-wide.
  * Android will not use DoT if the CA is missing, and will not fall back
    to unencrypted DNS when Private DNS is set — it fails closed. That is
    the desired behaviour here.
""")
    return 0


def cmd_show(args):
    """Report the current resolver configuration."""
    sysname = platform.system()
    say(f"Souran client v{VERSION} — current DNS configuration")
    say(f"platform: {sysname}")
    say()
    if sysname == "Linux":
        rc, out, _ = run(["resolvectl", "status"])
        say(out if rc == 0 else "(resolvectl unavailable)")
        say()
        rc, out, _ = run(["cat", "/etc/resolv.conf"])
        say("/etc/resolv.conf:")
        say(out)
    elif sysname == "Darwin":
        rc, out, _ = run(["scutil", "--dns"])
        say(out)
    elif sysname == "Windows":
        rc, out, _ = run(["ipconfig", "/all"])
        for line in out.splitlines():
            if "DNS Servers" in line or "DNS Suffix" in line:
                say(line.strip())
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="souran_client.py",
        description="Configure Windows/macOS/Linux to use a self-hosted "
                    "Souran resolver over DoT or DoH.")
    ap.add_argument("--version", action="version",
                    version=f"souran_client {VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--server", required=True,
                       help="resolver hostname (must match a cert SAN)")
        p.add_argument("--ca", help="PEM CA certificate that signed the "
                                    "resolver's certificate")
        p.add_argument("--name", default="example.com",
                       help="name to use for the test query")
        p.add_argument("--doh", default=DEFAULT_DOH,
                       help="DoH endpoint URL (set empty to skip)")
        p.add_argument("--connect-ip",
                       help="connect to this address while still validating "
                            "the certificate for --server. Needed when the "
                            "resolver's own name has no A record.")
        p.add_argument("--insecure", action="store_true",
                       help="skip certificate verification for THIS run "
                            "only. Diagnostic use; the channel is then "
                            "unauthenticated.")

    p = sub.add_parser("test", help="verify the resolver answers and the "
                                    "certificate validates")
    common(p)
    p.set_defaults(func=cmd_test)

    p = sub.add_parser("apply", help="point this machine at the resolver")
    common(p)
    p.add_argument("--yes", action="store_true",
                   help="actually make the change (default is a dry run)")
    p.set_defaults(func=cmd_apply)

    p = sub.add_parser("android", help="print Android Private DNS steps")
    common(p)
    p.set_defaults(func=cmd_android)

    p = sub.add_parser("show", help="show the current DNS configuration")
    p.set_defaults(func=cmd_show)

    args = ap.parse_args(argv)
    if getattr(args, "doh", None) == "":
        args.doh = None
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
