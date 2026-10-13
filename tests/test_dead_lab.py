"""1.1.0 dead-lab regression tests.

The reported failures ("it is still not solved") were NOT solver bugs: the
tested Academy instances were EXPIRED. The PortSwigger gateway keeps
answering for a dead instance with HTTP 504 and the body
"Server Error: Gateway Timeout (0) connecting to <host>" -- and 1.0.0's
probe treated ANY response as "reachable", so the scan burned minutes on a
corpse, produced nothing, and offered no explanation.

These tests pin the new behaviour:

  * the probe FAILS on the dead-lab signature and the scan aborts in
    seconds with an unmissable verdict + zero modules run;
  * the death is detected MID-RUN too (instance dies while scanning);
  * a plain 504 WITHOUT the signature is still treated as back-pressure
    (the academy also throttles with 504s) -- the two are told apart by
    BODY, not status;
  * the `check` CLI command returns the correct verdict + exit code.
"""

from __future__ import annotations

import socket
import threading
import time

import httpx
import pytest
import uvicorn
from click.testing import CliRunner
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse

from bughound.authorization import Scope
from bughound.cli import main as cli_main
from bughound.engine import run_scan
from bughound.http_client import HttpClient, lab_dead_response
from bughound.models import ScanConfig

DEAD_BODY = (
    "<html><head><title>Server Error: Gateway Timeout</title></head>"
    "<body><h1>Server Error: Gateway Timeout (0) connecting to "
    "0a05002a031c724e80fa1237001d00c4.web-security-academy.net</h1>"
    "</body></html>"
)

LIVE_BODY = (
    "<html><head><title>Not quite a lab</title></head><body>"
    "<div id=academyLabHeader><section class=academyLabBanner>"
    "<div class=title-container><h2>Mock live lab</h2></div>"
    "<div class='widgetcontainer-lab-status is-notsolved'><span>LAB</span>"
    "</div></section></div>"
    "<a href='/post?postId=1'>post</a></body></html>"
)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _serve(app: FastAPI):
    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    srv = uvicorn.Server(config)
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    for _ in range(50):
        if srv.started:
            break
        time.sleep(0.1)
    base = f"http://127.0.0.1:{port}/"
    return base, srv, thread


# ---------------------------------------------------------------------------
# unit: the death signature itself
# ---------------------------------------------------------------------------


def _resp(status: int, text: str, error: str | None = None):
    return httpx.Response(
        status,
        request=httpx.Request("GET", "http://t/"),
        text=text,
    )


def test_dead_signature_matches_gateway_body():
    class R:
        status = 504
        error = None
        text = DEAD_BODY

    assert lab_dead_response(R()) is True


def test_dead_signature_rejects_plain_gateway_timeout():
    """The academy throttles with 504s TOO -- a plain 'Gateway Timeout'
    body without the 'connecting to' phrasing is back-pressure, not death."""

    class R:
        status = 504
        error = None
        text = "<html><body>Gateway Timeout</body></html>"

    assert lab_dead_response(R()) is False


def test_dead_signature_rejects_other_statuses_and_errors():
    class R504Err:
        status = 504
        error = "ConnectError: boom"
        text = DEAD_BODY

    class R200:
        status = 200
        error = None
        text = DEAD_BODY

    class R403:
        status = 403
        error = None
        text = DEAD_BODY

    assert lab_dead_response(R504Err()) is False
    assert lab_dead_response(R200()) is False
    assert lab_dead_response(R403()) is False


def test_502_bad_gateway_signature_counts():
    class R:
        status = 502
        error = None
        text = "Server Error: Bad Gateway (0) connecting to lab.host"

    assert lab_dead_response(R()) is True


# ---------------------------------------------------------------------------
# unit: client-level fail-fast (no throttle sleeps on dead labs)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dead_lab_requests_do_not_throttle():
    """A dead-lab 504 must NOT open the adaptive back-off cooldown: sleeping
    2..35s per request was 1.0.0's second bug (6+ minute 'scans' of corpses)."""

    app = FastAPI()

    @app.get("/{path:path}")
    async def dead(path: str):
        return Response(content=DEAD_BODY, status_code=504, media_type="text/html")

    base, srv, thread = _serve(app)
    try:
        client = HttpClient(timeout=5.0)
        try:
            start = time.monotonic()
            for _ in range(4):
                resp = await client.get(base + "x")
                assert resp.status == 504
            elapsed = time.monotonic() - start
            assert client.lab_death_events == 4
            assert client.throttle_events == 0, (
                "dead-lab 504s must not register as throttle back-pressure"
            )
            assert elapsed < 10.0, (
                f"4 dead-lab requests took {elapsed:.1f}s -- throttle sleeps leaked in"
            )
        finally:
            await client.aclose()
    finally:
        srv.should_exit = True
        thread.join(timeout=5)


@pytest.mark.asyncio
async def test_plain_504_still_throttles():
    """Back-pressure 504s (no signature) keep the adaptive behaviour."""

    app = FastAPI()

    @app.get("/{path:path}")
    async def slow(path: str):
        return Response(content="<p>Gateway Timeout</p>", status_code=504)

    base, srv, thread = _serve(app)
    try:
        client = HttpClient(timeout=5.0)
        try:
            resp = await client.get(base)
            assert resp.status == 504
            assert client.throttle_events >= 1
            assert client.lab_death_events == 0
        finally:
            await client.aclose()
    finally:
        srv.should_exit = True
        thread.join(timeout=5)


# ---------------------------------------------------------------------------
# integration: pre-flight abort
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_aborts_fast_on_dead_lab():
    """The exact user scenario: scan an EXPIRED instance. Must abort in
    seconds with a loud verdict, an actionable error, and ZERO modules run."""

    app = FastAPI()

    @app.get("/{path:path}")
    async def dead(path: str):
        return Response(content=DEAD_BODY, status_code=504, media_type="text/html")

    base, srv, thread = _serve(app)
    try:
        config = ScanConfig(
            target_url=base,
            aggressive=True,
            use_external_tools=False,
            timeout=5.0,
        )
        scope = Scope(allowed_hosts=["127.0.0.1"])
        progress_log: list[str] = []
        start = time.monotonic()
        result = await run_scan(
            config, scope, confirmed=True, progress=lambda m: progress_log.append(m)
        )
        elapsed = time.monotonic() - start

        assert result.modules_run == [], (
            f"modules ran against a dead lab: {result.modules_run}"
        )
        assert result.stats.get("lab_dead") is True
        assert any("expired" in e.lower() or "dead" in e.lower() for e in result.errors), (
            f"errors do not explain the dead lab: {result.errors}"
        )
        log_text = "\n".join(progress_log)
        assert "DEAD / EXPIRED / STOPPED" in log_text, "verdict banner missing"
        assert "Access the lab" in log_text, "banner lacks next steps"
        assert elapsed < 30.0, f"dead-lab abort took {elapsed:.1f}s"
    finally:
        srv.should_exit = True
        thread.join(timeout=5)


# ---------------------------------------------------------------------------
# integration: death DURING the scan
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_detects_mid_run_lab_death():
    """Instance dies after the seed fetch: the phase guards must stop the
    scan loudly instead of grinding every module against the corpse."""

    app = FastAPI()
    state = {"hits": 0}

    @app.get("/{path:path}")
    async def dying(path: str, request: Request):
        state["hits"] += 1
        if state["hits"] <= 2:  # seed + first crawl fetch see a live lab
            return HTMLResponse(LIVE_BODY)
        return Response(content=DEAD_BODY, status_code=504, media_type="text/html")

    base, srv, thread = _serve(app)
    try:
        config = ScanConfig(
            target_url=base,
            aggressive=True,
            use_external_tools=False,
            timeout=5.0,
            max_urls=5,
        )
        scope = Scope(allowed_hosts=["127.0.0.1"])
        progress_log: list[str] = []
        start = time.monotonic()
        result = await run_scan(
            config, scope, confirmed=True, progress=lambda m: progress_log.append(m)
        )
        elapsed = time.monotonic() - start

        assert result.stats.get("lab_dead") is True, "mid-run death not detected"
        assert any("died mid-scan" in e for e in result.errors), (
            f"no mid-scan death error: {result.errors}"
        )
        log_text = "\n".join(progress_log)
        assert "DEAD / EXPIRED / STOPPED" in log_text
        assert elapsed < 60.0, f"mid-run abort took {elapsed:.1f}s"
    finally:
        srv.should_exit = True
        thread.join(timeout=5)


# ---------------------------------------------------------------------------
# integration: live lab still scans normally (no false death verdicts)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_live_lab_still_scans():
    app = FastAPI()

    @app.get("/")
    async def home(request: Request):
        return HTMLResponse(LIVE_BODY)

    @app.get("/post")
    async def post(request: Request, postId: str = "1"):
        return HTMLResponse(LIVE_BODY)

    base, srv, thread = _serve(app)
    try:
        config = ScanConfig(
            target_url=base,
            aggressive=False,
            use_external_tools=False,
            timeout=5.0,
            max_urls=5,
        )
        scope = Scope(allowed_hosts=["127.0.0.1"])
        progress_log: list[str] = []
        result = await run_scan(
            config, scope, confirmed=True, progress=lambda m: progress_log.append(m)
        )
        assert result.modules_run, "live lab skipped modules"
        assert result.stats.get("lab_dead") is None
        assert "\n".join(progress_log).count("DEAD") == 0
    finally:
        srv.should_exit = True
        thread.join(timeout=5)


# ---------------------------------------------------------------------------
# CLI: the `check` command
# ---------------------------------------------------------------------------


def test_check_command_dead_verdict():
    app = FastAPI()

    @app.get("/{path:path}")
    async def dead(path: str):
        return Response(content=DEAD_BODY, status_code=504, media_type="text/html")

    base, srv, thread = _serve(app)
    try:
        runner = CliRunner()
        result = runner.invoke(cli_main, ["check", base])
        assert result.exit_code == 1
        assert "DEAD / EXPIRED LAB" in result.output
        assert "Access the lab" in result.output
    finally:
        srv.should_exit = True
        thread.join(timeout=5)


def test_check_command_alive_verdict():
    app = FastAPI()

    @app.get("/")
    async def home():
        return HTMLResponse(LIVE_BODY)

    base, srv, thread = _serve(app)
    try:
        runner = CliRunner()
        result = runner.invoke(cli_main, ["check", base])
        assert result.exit_code == 0, result.output
        assert "ALIVE" in result.output
        assert "Mock live lab" in result.output
    finally:
        srv.should_exit = True
        thread.join(timeout=5)
