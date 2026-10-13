"""Oracle "valid literal" trap regression test (1.1.1).

The REAL Academy Oracle lab ("SQL injection attack, listing the database
contents on Oracle") renders UNION-extraction useless unless the engine
handles one specific trap:

    In the backend query ``... WHERE category = '<value>'`` EVERY category
    value -- including the engine's UNQUOTED payloads -- ends up inside the
    string literal. ``Gifts UNION SELECT NULL,NULL-- -`` is therefore a
    VALID query (it just selects products whose category is that whole
    text) and the endpoint answers HTTP 200 with baseline rows only.

The 1.1.0 (and earlier) shape discovery collected candidates purely on
"status executed": on Oracle the QUOTED arms all error (they need FROM
dual), while the UNQUOTED arm always "succeeds" as a literal -- so the
plain loop hoarded three bogus candidates, the ``if not candidates:``
Oracle FROM-dual phase never ran, every validation failed, and
``discover_union_shape`` returned None. Result: "UNION credential
extraction ... attempted" then a 4-minute boolean-blind crawl -- the exact
"it still doesn't exploit the link" report.

The old dialect-lab mocks did NOT reproduce this: their /filter handler
errored (500) on any payload that did not match the quoted-UNION grammar,
so unquoted payloads never returned the misleading 200. This file builds
the faithful mock: unquoted/paren payloads are VALID LITERALS (200,
baseline rows only, no UNION executed), exactly like the real backend.
"""

from __future__ import annotations

import asyncio
import os
import re
import socket
import sys
import threading
import time

import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse

sys.path.insert(0, os.path.dirname(__file__))

from test_dialect_labs import (  # noqa: E402
    ORA_ERROR,
    _catalog,
    _split_top,
)

from bughound.exploits.sqli import (  # noqa: E402
    _credential_table_candidates,
    discover_credential_columns,
    discover_union_shape,
    exploit_sqli_union,
    extract_rows_union,
    probe_dialect,
)
from bughound.http_client import HttpClient  # noqa: E402
from bughound.models import (  # noqa: E402
    Category,
    Finding,
    ScanConfig,
    Severity,
    Target,
)
from bughound.modules.base import RequestTarget, ScanContext  # noqa: E402

_OUTER_COLUMNS = 2  # the vulnerable query selects (product_name, description)


def _parse_arm(category: str, catalog):
    """Oracle backend semantics for the injected value.

    Returns list-of-expr-values when a quoted UNION arm with FROM dual was
    injected (real execution), or None when the value stayed a plain string
    literal (the trap: HTTP 200, NO union row). Raises ValueError on real
    Oracle syntax errors (missing FROM dual / wrong column count).
    """
    m = re.match(r"^(?P<base>.*)' UNION SELECT (?P<row>.*)--.*$", category, re.S)
    if not m:
        # Whole value stays inside the SQL string literal -> valid query,
        # no UNION executed, baseline rows only.
        return None
    row = m.group("row")
    if not re.search(r"FROM\s+dual$", row, re.I):
        raise ValueError(ORA_ERROR)
    exprs = _split_top(re.sub(r"FROM\s+dual$", "", row, flags=re.I))
    if len(exprs) != _OUTER_COLUMNS:
        raise ValueError(ORA_ERROR)
    return [catalog.eval_expr(e) for e in exprs]


def build_oracle_trap_app(catalog) -> FastAPI:
    """Academy-styled shop whose backend reproduces the literal trap."""
    app = FastAPI()
    state = {"solved": False}
    products = [
        ("Leather Gloves", "Accessories"),
        ("Sunglasses", "Accessories"),
        ("Dog Toy", "Pets"),
    ]

    def _page(title: str, rows) -> str:
        status = "is-solved" if state["solved"] else "is-notsolved"
        body = "".join(f"<div>{n} -- {c}</div>" for n, c in rows)
        return (
            f"<html><head><title>{title}</title></head>"
            '<body><div id="academyLabHeader"><section class="academyLabBanner">'
            '<div class="container"><div class="title-container">'
            f"<h2>{title}</h2></div>"
            f'<div class="widgetcontainer-lab-status {status}"><span>LAB</span>'
            "</div></div></section></div>"
            "<a href='/filter?category=Accessories'>Accessories</a>"
            "<a href='/filter?category=Pets'>Pets</a>"
            "<a href='/my-account'>My account</a>"
            "<a href='/login'>Login</a>"
            + body
            + "</body></html>"
        )

    @app.get("/", response_class=HTMLResponse)
    def home():
        return _page(
            "SQL injection attack, listing the database contents on Oracle",
            [],
        )

    @app.get("/filter", response_class=HTMLResponse)
    def filter_products(category: str = ""):
        try:
            union_values = _parse_arm(category, catalog)
        except ValueError:
            return HTMLResponse(
                f"<html><body><pre>{ORA_ERROR}</pre></body></html>",
                status_code=500,
            )
        shown = [(n, c) for n, c in products if c == category]
        if union_values is not None:
            shown.append(
                tuple(v if v is not None else "NULL" for v in union_values)
            )
        # NOTE: the real Academy lab does NOT echo the category value into
        # the page (verified against a live instance), so the mock must not
        # either -- an echo would reflect the probe markers without any
        # UNION execution and defeat the very validation under test.
        links = (
            "<a class=filter href='/filter?category=Accessories'>Accessories</a>"
            "<a class=filter href='/filter?category=Pets'>Pets</a>"
        )
        return HTMLResponse(
            "<html><body>" + links
            + "".join(f"<div>{n} -- {c}</div>" for n, c in shown)
            + "</body></html>"
        )

    @app.get("/login", response_class=HTMLResponse)
    def login_form():
        return (
            "<html><body><form method=POST action=/login>"
            "<input name=csrf value=token123><input name=username>"
            "<input name=password><button type=submit>Log in</button>"
            "</form></body></html>"
        )

    @app.post("/login")
    async def login(request: Request):
        form = await request.form()
        user = str(form.get("username", ""))
        pwd = str(form.get("password", ""))
        table = list(catalog.rows)[0]
        creds = {u: p for u, p in catalog.rows[table]}
        if creds.get(user) == pwd:
            if user == "administrator":
                state["solved"] = True
            resp = RedirectResponse("/", status_code=303)
            resp.set_cookie("session", f"owned-by-{user}")
            return resp
        return HTMLResponse(
            "<html><body>Invalid username or password.</body></html>",
            status_code=401,
        )

    app.state.solved_flag = state
    return app


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture()
def trap_lab():
    catalog = _catalog("Oracle")
    app = build_oracle_trap_app(catalog)
    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    srv = uvicorn.Server(config)
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    for _ in range(50):
        if srv.started:
            break
        time.sleep(0.1)
    url = f"http://127.0.0.1:{port}/"
    yield catalog, url, app.state.solved_flag
    srv.should_exit = True
    thread.join(timeout=5)


def _make_ctx(server: str):
    client = HttpClient(timeout=10)
    m_port = re.search(r":(\d+)/", server)
    port = int(m_port.group(1)) if m_port else 80
    config = ScanConfig(
        target_url=server, aggressive=True, exploit=True, use_external_tools=False
    )
    target = Target(url=server, scheme="http", host="127.0.0.1", port=port, authorized=True)
    rt_filter = RequestTarget(
        url=server + "filter", method="GET", params={"category": "Accessories"},
        source="direct",
    )
    rt_login = RequestTarget(
        url=server + "login", method="POST",
        params={"username": "", "password": "", "csrf": ""}, source="form",
    )
    seed = (
        '<html><head><title>SQL injection attack, listing the database contents'
        "</title></head><body><div id=\"academyLabHeader\">"
        "<div class='widgetcontainer-lab-status is-notsolved'><p>Not solved</p>"
        "</div></div></body></html>"
    )
    ctx = ScanContext(
        client=client,
        config=config,
        target=target,
        base_url=server,
        urls=[server],
        request_targets=[rt_filter, rt_login],
        seed_html=seed,
    )
    return ctx, client, rt_filter


def _sqli_finding(server: str) -> Finding:
    return Finding(
        category=Category.SQLI,
        title="Possible boolean-based SQL injection in 'category'",
        severity=Severity.CRITICAL,
        url=server + "filter",
        module="sqli",
        verified=True,
    )


def test_trap_mock_reproduces_the_literal_200(trap_lab):
    """Sanity: unquoted payloads MUST return 200 with NO union row (the trap),
    and quoted FROM-dual arms MUST execute. If this ever changes, the mock
    no longer models the real lab."""
    catalog, server, _ = trap_lab
    ctx, client, rt = _make_ctx(server)

    async def run():
        # unquoted payload: valid literal -> 200, no injected row
        r = await ctx.client.get(
            server
            + "filter?category="
            + "Accessories%20UNION%20SELECT%20NULL%2CNULL--%20-"
        )
        assert r.status == 200 and "bhstr" not in r.text
        # quoted FROM-dual arm: real execution -> row appears
        r2 = await ctx.client.get(
            server
            + "filter?category=Accessories%27%20UNION%20SELECT%20%27bhstr0%3D%27%2CNULL%20FROM%20dual--%20-"
        )
        assert r2.status == 200 and "bhstr0= -- NULL" in r2.text
        # quoted arm WITHOUT FROM dual: Oracle error
        r3 = await ctx.client.get(
            server
            + "filter?category=Accessories%27%20UNION%20SELECT%20%27xy%27%2CNULL--%20-"
        )
        assert r3.status == 500
        await client.aclose()

    asyncio.run(run())


def test_shape_discovery_survives_the_trap(trap_lab):
    """THE regression: shape discovery must reach the Oracle FROM-dual phase
    even though the plain phase hoards 200-OK bogus literal candidates.
    1.1.0 returned None here; the fixed engine returns cols=2/from_dual."""
    catalog, server, _ = trap_lab
    ctx, client, rt = _make_ctx(server)

    async def run():
        try:
            shape = await discover_union_shape(ctx, rt, "category")
            assert shape is not None, (
                "discover_union_shape returned None on a working Oracle UNION point"
            )
            assert shape.cols == 2
            assert shape.from_dual is True
            assert shape.wrapper.startswith("Accessories")
        finally:
            await client.aclose()

    asyncio.run(run())


def test_full_oracle_extraction_and_login(trap_lab):
    """End-to-end: dialect probe -> all_tables -> all_tab_columns -> credential
    rows -> automated administrator login. Mirrors what the real lab needs."""
    catalog, server, flag = trap_lab
    ctx, client, rt = _make_ctx(server)

    async def run():
        try:
            shape = await discover_union_shape(ctx, rt, "category")
            assert shape is not None
            await probe_dialect(ctx, rt, "category", shape)
            assert shape.dialect == "Oracle"
            cands = _credential_table_candidates(shape.tables)
            assert cands and cands[0].startswith("USERS_")
            pairs = await discover_credential_columns(ctx, rt, "category", shape, cands[0])
            rows = []
            for ucol, pcol in pairs[:4]:
                rows = await extract_rows_union(ctx, rt, "category", shape, cands[0], ucol, pcol)
                if rows:
                    break
            assert ("administrator", "0raclePwn2024!") in rows

            # Full exploit finding: extraction + automated login.
            f2 = await exploit_sqli_union(ctx, _sqli_finding(server), rt, "category")
            assert f2.exploit_status == "succeeded"
            joined = " ".join(f2.extracted_data)
            assert "ACCOUNT TAKEOVER" in joined
            assert flag["solved"] is True
        finally:
            await client.aclose()

    asyncio.run(run())
