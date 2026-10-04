#!/usr/bin/env python3
"""
Souran v5.0.0 — Authentication middleware conformance test.

Exercises souran_auth through a real ASGI app with genuinely distinct
client addresses. Earlier revisions of this test used TestClient's default
peer (always "testclient") and asserted on it, which produced three
false failures; the client address must be injected into the scope to
test anything meaningful.
"""
import os
import sys

# tests/ lives one level below the package root, so the root — not the
# script's own directory — is what has to be importable.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import souran_auth
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()


# Mirrors the exemption list in sidecar.py exactly. A test harness that
# omits production's exemptions tests a different middleware than the one
# that ships, which is how "the test passes but prod 401s health checks"
# bugs are born.
EXEMPT = ("/api/health", "/docs", "/openapi.json", "/redoc")


@app.middleware("http")
async def mw(request: Request, call_next):
    if request.url.path in EXEMPT:
        return await call_next(request)
    host = request.client.host if request.client else ""
    if not souran_auth.authorize(host,
                                 headers=dict(request.headers),
                                 query=request.url.query,
                                 cookies=request.cookies):
        return JSONResponse({"error": "unauthorized"}, status_code=401,
                            headers={"WWW-Authenticate": "Bearer"})
    return await call_next(request)


@app.get("/api/secret")
async def secret():
    return {"secret": "ok"}


@app.get("/api/health")
async def health():
    return {"status": "ok"}


TOKEN = souran_auth.load_token()


def probe(ip, headers=None, path="/api/secret"):
    """Issue a GET as `ip` by injecting the peer into the ASGI scope.

    TestClient always reports the peer as "testclient", so testing
    loopback-vs-remote through it asserts nothing. Driving the raw ASGI
    callable lets each case carry a real distinct address.
    """
    import anyio
    scope = {
        "type": "http", "asgi": {"version": "3.0"},
        "http_version": "1.1", "method": "GET", "path": path,
        "raw_path": path.encode(), "query_string": b"",
        "root_path": "", "scheme": "http",
        "headers": [(k.lower().encode(), v.encode())
                    for k, v in (headers or {}).items()],
        "client": (ip, 40000), "server": ("127.0.0.1", 9192),
    }

    async def run():
        send = []
        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send_(msg):
            send.append(msg)
        await app(scope, receive, send_)
        status = next((m["status"] for m in send if m["type"] == "http.response.start"), None)
        return status

    return anyio.run(run)


CASES = [
    # (name, ip, headers, path, expected)
    ("loopback no token",        "127.0.0.1",  {},  "/api/secret", 200),
    ("loopback .5",              "127.0.0.5",  {},  "/api/secret", 200),
    ("ipv6 loopback",            "::1",        {},  "/api/secret", 200),
    ("v4-mapped loopback",       "::ffff:127.0.0.1", {}, "/api/secret", 200),
    ("LAN no token",             "10.1.1.1",   {},  "/api/secret", 401),
    ("LAN wrong token",          "10.1.1.1",   {"Authorization": "Bearer nope"}, "/api/secret", 401),
    ("LAN correct bearer",       "10.1.1.1",   {"Authorization": "Bearer " + TOKEN}, "/api/secret", 200),
    ("LAN correct X-Api-Token",  "10.1.1.1",   {"X-Api-Token": TOKEN}, "/api/secret", 200),
    ("LAN UPPERCASE hdr",        "10.1.1.1",   {"X-API-TOKEN": TOKEN}, "/api/secret", 200),
    ("LAN token prefix",         "10.1.1.1",   {"Authorization": "Bearer " + TOKEN[:-1]}, "/api/secret", 401),
    ("LAN token +1 char",        "10.1.1.1",   {"Authorization": "Bearer " + TOKEN + "x"}, "/api/secret", 401),
    ("LAN empty bearer",         "10.1.1.1",   {"Authorization": "Bearer "}, "/api/secret", 401),
    ("public no token",          "185.220.100.247", {}, "/api/secret", 401),
    ("public correct token",     "185.220.100.247", {"Authorization": "Bearer " + TOKEN}, "/api/secret", 200),
    ("health exempt (remote)",   "185.220.100.247", {}, "/api/health", 200),
]

fails = []
print("=" * 66)
print("Souran v5.0.0 — auth middleware conformance")
print("=" * 66)
for name, ip, hdrs, path, want in CASES:
    got = probe(ip, hdrs, path)
    ok = got == want
    print(f"{'PASS' if ok else 'FAIL'}  {name:26} {ip:18} got={got} want={want}")
    if not ok:
        fails.append(name)

print()
print(f"{len(CASES) - len(fails)}/{len(CASES)} passed")
if fails:
    print("FAILURES: " + ", ".join(fails))
    sys.exit(1)
print("ALL AUTH TESTS PASS")