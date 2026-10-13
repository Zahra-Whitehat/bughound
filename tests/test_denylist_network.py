"""Prove the denylist stops requests before they reach the network."""

import socket
import threading
import time

import pytest
import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, RedirectResponse

from bughound.authorization import Scope
from bughound.crawler import crawl
from bughound.http_client import HttpClient

HITS: dict[str, int] = {}


def _make_app() -> FastAPI:
    app = FastAPI()

    @app.get("/", response_class=HTMLResponse)
    def index():
        HITS["/"] = HITS.get("/", 0) + 1
        # Links to an allowed page and a forbidden page.
        return (
            '<a href="/ok">ok</a>'
            '<a href="/forbidden">forbidden</a>'
            '<a href="/forbidden/deep">deep</a>'
        )

    @app.get("/ok", response_class=HTMLResponse)
    def ok():
        HITS["/ok"] = HITS.get("/ok", 0) + 1
        return "ok"

    @app.get("/forbidden", response_class=HTMLResponse)
    def forbidden():
        HITS["/forbidden"] = HITS.get("/forbidden", 0) + 1
        return "SHOULD NEVER BE REQUESTED"

    @app.get("/forbidden/deep", response_class=HTMLResponse)
    def forbidden_deep():
        HITS["/forbidden/deep"] = HITS.get("/forbidden/deep", 0) + 1
        return "SHOULD NEVER BE REQUESTED"

    @app.get("/goredirect")
    def goredirect():
        HITS["/goredirect"] = HITS.get("/goredirect", 0) + 1
        return RedirectResponse(url="/forbidden")

    return app


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture()
def server():
    HITS.clear()
    port = _free_port()
    config = uvicorn.Config(_make_app(), host="127.0.0.1", port=port, log_level="warning")
    srv = uvicorn.Server(config)
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    for _ in range(50):
        if srv.started:
            break
        time.sleep(0.1)
    yield f"http://127.0.0.1:{port}"
    srv.should_exit = True
    thread.join(timeout=5)


@pytest.mark.asyncio
async def test_http_client_blocks_denied_url(server):
    scope = Scope(allowed_hosts=["127.0.0.1"], denied_urls=[f"{server}/forbidden"])
    client = HttpClient(blocked=scope.url_denied)
    try:
        # Allowed request goes through.
        ok = await client.get(f"{server}/ok")
        assert ok.status == 200
        # Denied request never reaches the server.
        blocked = await client.get(f"{server}/forbidden")
        assert blocked.status == 0
        assert "DeniedTargetError" in (blocked.error or "")
    finally:
        await client.aclose()

    assert HITS.get("/forbidden", 0) == 0
    assert client.blocked_requests


@pytest.mark.asyncio
async def test_redirect_into_denied_is_blocked(server):
    scope = Scope(allowed_hosts=["127.0.0.1"], denied_urls=[f"{server}/forbidden"])
    client = HttpClient(blocked=scope.url_denied)
    try:
        resp = await client.get(f"{server}/goredirect")
        # The redirect target is denied, so it is refused rather than followed.
        assert resp.status == 0
        assert "DeniedTargetError" in (resp.error or "")
    finally:
        await client.aclose()
    assert HITS.get("/forbidden", 0) == 0


@pytest.mark.asyncio
async def test_crawler_never_enters_denied(server):
    scope = Scope(allowed_hosts=["127.0.0.1"], denied_urls=[f"{server}/forbidden"])
    client = HttpClient(blocked=scope.url_denied)
    try:
        visited, _targets, _html, _headers = await crawl(
            client, f"{server}/", max_urls=20, max_depth=2, is_denied=scope.url_denied
        )
    finally:
        await client.aclose()

    assert any(u.endswith("/ok") for u in visited)
    assert not any("/forbidden" in u for u in visited)
    assert HITS.get("/forbidden", 0) == 0
    assert HITS.get("/forbidden/deep", 0) == 0
