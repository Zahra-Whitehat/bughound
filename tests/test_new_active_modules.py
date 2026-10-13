"""Integration tests for the 0.7 active modules (jwt/xxe/graphql/host-header/
prototype-pollution/default-logins gating) against the local vulnerable app.

Each module is exercised through a hand-built ScanContext so the test
targets the module logic directly (the demo app provides real endpoints).
"""

from __future__ import annotations

import socket
import threading
import time
from urllib.parse import urlparse

import pytest
import uvicorn

from bughound.http_client import HttpClient
from bughound.models import Category, ScanConfig, Target
from bughound.modules.active.default_logins import DefaultLoginsModule
from bughound.modules.active.graphql_hunter import GraphqlHunterModule
from bughound.modules.active.host_header_poison import HostHeaderPoisonModule
from bughound.modules.active.jwt_attacks import decode_jwt, sign_jwt
from bughound.modules.active.prototype_pollution import PrototypePollutionModule
from bughound.modules.active.xxe_prober import XxeProberModule
from bughound.modules.base import RequestTarget, ScanContext
from examples.vulnerable_app import app as vuln_app


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def server():
    port = _free_port()
    config = uvicorn.Config(vuln_app, host="127.0.0.1", port=port, log_level="warning")
    srv = uvicorn.Server(config)
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    for _ in range(50):
        if srv.started:
            break
        time.sleep(0.1)
    yield f"http://127.0.0.1:{port}/"
    srv.should_exit = True
    thread.join(timeout=5)


def _make_ctx(server: str, request_targets: list[RequestTarget] | None = None,
              bruteforce: bool = False) -> ScanContext:
    client = HttpClient(timeout=10)
    config = ScanConfig(target_url=server, use_external_tools=False, bruteforce=bruteforce)
    port = urlparse(server).port or 80
    target = Target(url=server, scheme="http", host="127.0.0.1", port=port, authorized=True)
    return ScanContext(
        client=client,
        config=config,
        target=target,
        base_url=server,
        urls=[server],
        request_targets=request_targets or [],
    )


# ---------------------------------------------------------------------------
# jwt-attacks
# ---------------------------------------------------------------------------


def test_jwt_helpers_roundtrip():

    tok = sign_jwt({"alg": "HS256", "typ": "JWT"}, {"user": "admin"}, "secret")
    header, payload = decode_jwt(tok)
    assert header["alg"] == "HS256"
    assert payload["user"] == "admin"
    # none-signing strips the signature.
    none_tok = sign_jwt({"alg": "HS256"}, {"user": "admin"}, "", "none")
    assert none_tok.endswith(".")


@pytest.mark.asyncio
async def test_jwt_module_flags_alg_none_on_demo_app(server):
    ctx = _make_ctx(server)
    # Obtain the demo app's weak-secret JWT session cookie.
    r = await ctx.client.get(server + "jwt")
    assert r.ok
    assert any(c.name == "jwt_session" for c in ctx.client._client.cookies.jar)
    ctx.base_url = server + "jwt"  # acceptance checks hit the JWT-gated page

    findings = await __import__(
        "bughound.modules.active.jwt_attacks", fromlist=["JwtAttacksModule"]
    ).JwtAttacksModule().run(ctx)

    titles = [f.title for f in findings]
    assert any("alg=none" in t for t in titles), titles
    alg_none = next(f for f in findings if "alg=none" in f.title)
    assert alg_none.severity.value == "critical"
    assert alg_none.verified
    # The wrong-secret control was rejected on this app, so the "no
    # verification at all" finding must NOT be present.
    assert not any("not verified at all" in t for t in titles)
    await ctx.client.aclose()


# ---------------------------------------------------------------------------
# xxe-prober
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_xxe_prober_finds_file_disclosure(server):
    rt = RequestTarget(url=server + "import-xml", method="POST", params={})
    ctx = _make_ctx(server, [rt])
    findings = await XxeProberModule().run(ctx)
    assert findings, "expected an XXE finding against /import-xml"
    f = findings[0]
    assert f.category == Category.XXE
    assert f.verified
    assert "passwd" in f.evidence or "entity" in f.evidence.lower()
    await ctx.client.aclose()


# ---------------------------------------------------------------------------
# graphql-hunter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_graphql_hunter_finds_introspection(server):
    ctx = _make_ctx(server)
    findings = await GraphqlHunterModule().run(ctx)
    assert findings
    assert any("introspection enabled" in f.title for f in findings)
    intro = next(f for f in findings if "introspection enabled" in f.title)
    assert intro.verified
    assert "6 types" in intro.title or "types disclosed" in intro.title
    await ctx.client.aclose()


# ---------------------------------------------------------------------------
# host-header-poison
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_host_header_poison_detects_reset_link_reflection(server):
    rt = RequestTarget(url=server + "reset", method="GET", params={})
    ctx = _make_ctx(server, [rt])
    findings = await HostHeaderPoisonModule().run(ctx)
    assert findings, "expected host-header reflection finding on /reset"
    f = findings[0]
    assert f.verified
    assert "bhhost-" in f.evidence
    await ctx.client.aclose()


# ---------------------------------------------------------------------------
# prototype-pollution
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_prototype_pollution_server_side_merge(server):
    rt = RequestTarget(url=server + "api/merge", method="POST", params={})
    ctx = _make_ctx(server, [rt])
    findings = await PrototypePollutionModule().run(ctx)
    assert findings
    f = findings[0]
    assert "prototype-pollution sink" in f.title
    assert f.verified
    await ctx.client.aclose()


# ---------------------------------------------------------------------------
# default-logins gating (Sn1per -b style, strictly opt-in)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_default_logins_disabled_without_brute_flag(server):
    rt = RequestTarget(
        url=server + "login", method="POST", params={"username": "", "password": ""}
    )
    ctx = _make_ctx(server, [rt], bruteforce=False)
    findings = await DefaultLoginsModule().run(ctx)
    assert findings == []


@pytest.mark.asyncio
async def test_default_logins_no_false_positive_on_correct_creds(server):
    # The demo app's real credentials are administrator/S3cret-wizard-pass,
    # which are NOT in the default-credential list -- so the check must run
    # (bruteforce enabled) and report nothing (no false positive).
    rt = RequestTarget(
        url=server + "login", method="POST", params={"username": "", "password": ""}
    )
    ctx = _make_ctx(server, [rt], bruteforce=True)
    findings = await DefaultLoginsModule().run(ctx)
    assert findings == []
    await ctx.client.aclose()
