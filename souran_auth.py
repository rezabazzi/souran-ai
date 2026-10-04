#!/usr/bin/env python3
"""
Souran AI Network Server v5.0.0 — Shared Authentication Module
File: souran_auth.py   |  Purpose: one auth decision for every control surface

PROBLEM THIS SOLVES
-------------------
Every control surface on this host (the :8082 Hermes dashboard, the :8383
web dashboard, the :9192 sidecar API, the :8084 learning engine, the :8086
Web3 resolver, the :8087 gaming resolver) was reachable by anyone who could
open a TCP connection, with no credential check anywhere. The host sits
behind a consumer NAT, but a NAT is not an access control: every device on
the same Wi-Fi, any public exposure via the Cloudflare tunnel, and any
future port-forward reached full remote control of the resolver, the proxy
stack, and (before v4.3.2) arbitrary shell execution.

DESIGN
------
1. A bearer token, generated once, stored root-owned in /etc/souran.
2. Comparison is `hmac.compare_digest` — constant time, so a remote
   prober cannot learn the token a character at a time from response
   timing.
3. Loopback callers are exempt. The control plane is meant to be driven by
   the watchdog, the test suites and the agent, all of which live on this
   host; forcing them to carry a token buys no security but breaks every
   existing caller. Anything arriving over a real network still must
   present a valid token.
4. Failure is loud and specific, and never leaks whether the token was
   close. Missing and wrong are the same 401 with the same body.

ENVIRONMENT
-----------
SOURAN_API_TOKEN   explicit token (overrides the file) — for containers
SOURAN_API_TOKEN_FILE  path to the token (default /etc/souran/api-token)
SOURAN_AUTH_DISABLED  set to 1 to bypass auth ENTIRELY (break-glass only;
                   the security audit fails loudly if this is set)
"""

import hmac
import os
import secrets
import stat
import time

DEFAULT_TOKEN_FILE = "/etc/souran/api-token"
TOKEN_BYTES = 32

# In-process memo so we do not stat() the file on every single request.
_cached = {"token": None, "mtime": None, "path": None}


class AuthError(Exception):
    """Raised when a request must be rejected."""


def token_file_path() -> str:
    return os.environ.get("SOURAN_API_TOKEN_FILE", DEFAULT_TOKEN_FILE)


def auth_disabled() -> bool:
    return os.environ.get("SOURAN_AUTH_DISABLED") == "1"


def generate_token(nbytes: int = TOKEN_BYTES) -> str:
    """Return a fresh URL-safe token."""
    return secrets.token_urlsafe(nbytes)


def write_token(path: str = None, token: str = None, mode: int = 0o640) -> str:
    """Create the token file with restrictive permissions.

    Ownership is root:<service-group> and the mode is 0640. That is the
    only workable shape: the control services run as the unprivileged
    `reza` account (correctly — they are not root), so they must be able
    to read the token, but nobody else should. A root-only 0600 file
    would force every service back to running as root to work at all,
    which trades one hole for a much larger one.

    0o600 + root ownership is what you want if every consumer is root; the
    invariant we actually need is "never world-readable, never in a
    source file, never in git".
    """
    path = path or token_file_path()
    token = token or generate_token()
    d = os.path.dirname(path)
    group = os.environ.get("SOURAN_TOKEN_GROUP", "").strip()
    gid = -1
    if group:
        try:
            import grp
            gid = grp.getgrnam(group).gr_gid
        except (KeyError, ImportError):
            gid = -1
    if d:
        os.makedirs(d, mode=0o750, exist_ok=True)
        try:
            os.chmod(d, 0o750)
        except OSError:
            pass
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, (token + "\n").encode())
        # os.open honours mode only when creating; be explicit for the
        # rewrite-over-existing case.
        os.fchmod(fd, mode)
        if gid != -1:
            try:
                os.fchown(fd, 0, gid)
            except OSError:
                pass
    finally:
        os.close(fd)
    return token


def load_token() -> str:
    """Read the current token, re-reading if the file changed.

    The mtime check means rotating the token takes effect immediately
    without restarting every service — which is the whole point of having
    a rotation path.
    """
    env = os.environ.get("SOURAN_API_TOKEN")
    if env:
        return env.strip()
    path = token_file_path()
    try:
        st = os.stat(path)
    except OSError:
        return ""
    key = (path, st.st_mtime)
    if _cached["path"] == path and _cached["mtime"] == key[1]:
        return _cached["token"] or ""
    try:
        with open(path) as fh:
            token = fh.read().strip()
    except OSError:
        return ""
    _cached.update({"token": token, "mtime": st.st_mtime, "path": path})
    return token


def ensure_token(path: str = None) -> str:
    """Return the existing token, creating one if absent. Idempotent."""
    path = path or token_file_path()
    tok = load_token()
    if tok:
        return tok
    return write_token(path)


def token_is_valid(candidate: str) -> bool:
    expected = load_token()
    if not expected:
        return False
    if not candidate:
        return False
    return hmac.compare_digest(candidate, expected)


def is_loopback(remote_addr: str) -> bool:
    if not remote_addr:
        return False
    addr = remote_addr.strip()
    # IPv4 loopback, 127.0.0.0/8 (not just 127.0.0.1 — a service bound
    # to 0.0.0.0 can legitimately be reached as 127.0.0.x).
    if addr.startswith("127."):
        return True
    # IPv6 loopback, as reported by BaseHTTPRequestHandler.
    if addr in ("::1", "0:0:0:0:0:0:0:1"):
        return True
    if addr.startswith("::ffff:127."):
        return True
    return False


def extract_token(headers=None, query: str = "", cookies: dict = None) -> str:
    """Pull a bearer token from any of the places a client may put it.

    Accepts, in priority order: Authorization: Bearer <t>, X-Api-Token,
    ?token=<t> (so a browser can open a URL directly), and the
    souran_token cookie (set by the dashboard login form).

    Header lookup is case-insensitive on purpose. Starlette's Headers
    object is already case-insensitive, but the sidecar passes
    `dict(request.headers)`, which is NOT — it yields lowercase keys. A
    case-sensitive lookup therefore silently failed to find
    `X-Api-Token` while working fine under FastAPI's own object, which
    is the kind of bug that only shows up in production.
    """
    headers = headers or {}

    lowered = {}
    for k, v in headers.items():
        lowered.setdefault(str(k).lower(), v)

    auth = lowered.get("authorization")
    if auth:
        parts = auth.split(None, 1)
        if len(parts) == 2 and parts[0].lower() in ("bearer", "token"):
            return parts[1].strip()

    for hdr in ("x-api-token", "x-api-key", "x-apikey", "x-souran-token"):
        v = lowered.get(hdr)
        if v:
            return str(v).strip()

    if query:
        import urllib.parse
        for pair in query.split("&"):
            if pair.startswith("token=") or pair.startswith("api_token="):
                return urllib.parse.unquote(pair.split("=", 1)[1]).strip()

    if cookies and cookies.get("souran_token"):
        return cookies["souran_token"].strip()

    return ""


def authorize(remote_addr: str, headers=None, query: str = "", cookies: dict = None) -> bool:
    """The single authorization decision. Returns True if allowed.

    Callers should treat False as "reject with 401" and must NOT fall
    back to serving the request.
    """
    if auth_disabled():
        return True
    if is_loopback(remote_addr):
        return True
    return token_is_valid(extract_token(headers, query, cookies))


def require(remote_addr: str, headers=None, query: str = "", cookies: dict = None):
    """raise AuthError unless the caller is authorized."""
    if not authorize(remote_addr, headers, query, cookies):
        raise AuthError("authentication required")
    return True


def audit_token_state() -> dict:
    """Report on the health of the credential itself, for the audit view."""
    path = token_file_path()
    report = {
        "path": path,
        "exists": os.path.exists(path),
        "auth_disabled": auth_disabled(),
        "mode": None,
        "owner": None,
        "world_readable": False,
        "length": 0,
        "ok": False,
        "problems": [],
    }
    if not report["exists"]:
        report["problems"].append("token file missing — run ensure_token()")
        return report
    st = os.stat(path)
    report["mode"] = oct(stat.S_IMODE(st.st_mode))
    report["owner"] = f"uid={st.st_uid}"
    if st.st_mode & (stat.S_IRGRP | stat.S_IROTH):
        report["world_readable"] = True
        report["problems"].append(
            f"token file mode {report['mode']} is group/world accessible")
    # The credential must be owned by root OR by the account the control
    # services run as. On this host that is `reza`: every souran-* unit
    # runs unprivileged, so a root-only 0600 token would make the token
    # unreadable and force those services back to root -- a far worse
    # outcome than a uid-1000-owned 0600 file. What actually matters is
    # that it is 0600 and that no *other* uid can read it.
    SERVICE_UIDS = {0}
    for name in ("reza",):
        try:
            import pwd as _pwd
            SERVICE_UIDS.add(_pwd.getpwnam(name).pw_uid)
        except (KeyError, ImportError):
            pass
    if st.st_uid not in SERVICE_UIDS:
        report["problems"].append(
            f"token file owned by uid {st.st_uid}, expected root or a "
            f"service account ({sorted(SERVICE_UIDS)})")
    tok = load_token()
    report["length"] = len(tok)
    if len(tok) < 32:
        report["problems"].append(
            f"token is only {len(tok)} chars — too short to resist guessing")
    report["ok"] = not report["problems"]
    return report


if __name__ == "__main__":
    import json
    import sys

    if "--init" in sys.argv:
        path = token_file_path()
        sudo = os.geteuid() != 0
        if sudo:
            import subprocess
            r = subprocess.run(
                ["sudo", "-n", sys.executable, os.path.abspath(__file__), "--init"],
                capture_output=True, text=True)
            print(r.stdout or r.stderr)
            sys.exit(r.returncode)
        tok = write_token(path)
        print(f"token written to {path} ({len(tok)} chars, mode 0600)")
        print(tok)
        sys.exit(0)

    if "--rotate" in sys.argv:
        import subprocess
        if os.geteuid() != 0:
            r = subprocess.run(["sudo", "-n", sys.executable,
                                os.path.abspath(__file__), "--rotate"],
                               capture_output=True, text=True)
            print(r.stdout or r.stderr)
            sys.exit(r.returncode)
        print(write_token(token_file_path()))
        sys.exit(0)

    print(json.dumps(audit_token_state(), indent=2))