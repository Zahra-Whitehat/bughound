"""END-TO-END: 'Blind SQL injection with time delays' must solve.

The time-delays lab family is the fourth blind-SQLi transport: it has NO
boolean page differential, NO status-flip oracle and NO visible error text
-- the only observable is response TIME. The 1.5.0 ladder burned its budget
on boolean/error calibration (both correctly absent) and never engaged.
These tests pin the fix:

1. ladder: the title drives 'sqli-time-delay-objective' ahead of the
   boolean/error oracle strategy;
2. calibration: the delay oracle confirms only when the delay SCALES with
   the requested duration (2s probe -> ~2s, 4s probe -> ~4s); fixed slow
   responses and fast responses are rejected;
3. e2e: the FULL pipeline must calibrate the delay oracle on the TrackingId
   cookie, fire the lab's ~10s objective delay, and flip the mock's solved
   banner (real seconds, faithful to the live lab);
4. extraction ('...and information processing' variant): conditional
   CASE-WHEN delays answer yes/no questions in seconds; the bounded binary
   search recovers the administrator password and logs in.
"""

from __future__ import annotations

import asyncio

import pytest

from mock_academy import (
    TIME_DELAY_INFO_TITLE,
    TIME_DELAY_TITLE,
    build_time_delay_lab,
    lab_server,
)

from bughound.authorization import Scope
from bughound.engine import run_scan
from bughound.exploits.sqli import (
    calibrate_delay_oracle,
    exploit_sqli_delay_extraction,
)
from bughound.models import Category, ScanConfig, Severity, Target
from bughound.modules.base import RequestTarget, ScanContext
from bughound.http_client import HttpClient
from bughound.objectives import STRATEGIES, build_ladder


def _config(base: str) -> ScanConfig:
    return ScanConfig(
        target_url=base,
        aggressive=True,
        exploit=True,
        use_external_tools=False,
        max_urls=20,
        max_depth=2,
        timeout=20,
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


def test_ladder_prefers_time_delay_strategy():
    """The time-delays title must promote the time-delay strategy FIRST --
    boolean/error calibration is wasted budget on this family."""
    names = [s.name for s in build_ladder(TIME_DELAY_TITLE, None)]
    assert names[0] == "sqli-time-delay-objective"
    assert "sqli-blind-cookie-oracle" in names  # still available as fallback
    assert any(s.name == "sqli-time-delay-objective" for s in STRATEGIES)
    # The information-processing variant title matches too.
    assert build_ladder(TIME_DELAY_INFO_TITLE, None)[0].name == "sqli-time-delay-objective"


def test_delay_calibration_scales_and_rejects():
    """Calibration confirms the PG dialect on the mock and rejects
    non-scaling candidates (fast app; fixed slow app)."""
    app, _state, _pw = build_time_delay_lab()
    with lab_server(app) as base:

        async def probe():
            client = HttpClient(timeout=20)
            ctx = ScanContext(
                client=client, base_url=base, config=_config(base), target=_target(base)
            )
            try:
                await client.get(base)  # seed visit sets the TrackingId cookie
                rt = RequestTarget(url=base, method="GET", params={}, source="seed")
                return await calibrate_delay_oracle(ctx, rt, "cookie:TrackingId")
            finally:
                await client.aclose()

        oracle = asyncio.run(probe())
        assert oracle is not None, "delay oracle not calibrated on the mock"
        assert oracle.dialect == "PostgreSQL"

    # A fixed-2s app (slow, but the delay does NOT scale) must be rejected.
    from fastapi import FastAPI, Request
    from fastapi.responses import HTMLResponse

    from mock_academy import lab_page

    fixed = FastAPI()

    @fixed.get("/")
    async def fixed_home(request: Request):
        await asyncio.sleep(2)
        return HTMLResponse(
            lab_page("Blind SQL injection with time delays", "shop", False)
        )

    with lab_server(fixed) as base:

        async def probe2():
            client = HttpClient(timeout=20)
            ctx = ScanContext(
                client=client, base_url=base, config=_config(base), target=_target(base)
            )
            try:
                await client.get(base)
                rt = RequestTarget(url=base, method="GET", params={}, source="seed")
                return await calibrate_delay_oracle(ctx, rt, "cookie:TrackingId")
            finally:
                await client.aclose()

        assert asyncio.run(probe2()) is None, "fixed delay must not calibrate"


def test_e2e_time_delay_lab_solves():
    """The full pipeline must solve the simple time-delays lab: calibrate the
    delay oracle on the TrackingId cookie, fire the ~10s objective delay,
    flip the platform banner."""
    app, state, _pw = build_time_delay_lab()
    with lab_server(app) as base:
        result = _run(base)
        assert state.solved, "time-delays lab banner never flipped"
        assert result.objective and result.objective.get("solved_after") is True
        assert result.objective.get("title") == TIME_DELAY_TITLE
        delay_sqli = [
            f for f in result.findings
            if f.category == Category.SQLI and "Time-based blind SQL injection" in f.title
        ]
        assert delay_sqli, "no time-based SQLi finding recorded"
        # The objective delay evidence must be on the finding.
        assert any(
            "Objective delay fired" in line
            for f in delay_sqli
            for line in f.extracted_data
        ), "objective-delay evidence missing"


def test_delay_extraction_info_processing_solves():
    """The 'information processing' variant: conditional CASE-WHEN delays
    answer yes/no questions; the binary search recovers the administrator
    password and the engine logs in (banner flips on the login)."""
    import bughound.exploits.sqli as sqli_mod

    app, state, password = build_time_delay_lab(info_processing=True)
    with lab_server(app) as base:

        async def probe():
            client = HttpClient(timeout=20)
            ctx = ScanContext(
                client=client, base_url=base, config=_config(base), target=_target(base)
            )
            finding = sqli_mod.Finding(
                category=Category.SQLI,
                title="Time-based blind SQL injection in 'cookie:TrackingId' (PostgreSQL)",
                severity=Severity.CRITICAL,
                confidence="confirmed",
                url=base,
                module="test",
            )
            try:
                await client.get(base)  # seed visit sets the TrackingId cookie
                rt = RequestTarget(url=base, method="GET", params={}, source="seed")
                # The crawler normally records the login form; register it the
                # same way so the exploit chain can attempt the login.
                ctx.request_targets.append(
                    RequestTarget(url=base + "/login", method="POST",
                                  params={"username": "", "password": ""}, source="form")
                )
                oracle = await calibrate_delay_oracle(ctx, rt, "cookie:TrackingId")
                assert oracle is not None
                await exploit_sqli_delay_extraction(ctx, finding, rt, "cookie:TrackingId", oracle)
                return finding
            finally:
                await client.aclose()

        # Tighten the ask constants for test speed (real seconds otherwise):
        # TRUE answers sleep 1s, FALSE answers return immediately; the 0.5s
        # floor still separates them by construction (asyncio.sleep(1) >= 1).
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(sqli_mod, "DELAY_ASK_SECONDS", 1)
            mp.setattr(sqli_mod, "DELAY_TRUE_FLOOR", 0.5)
            finding = asyncio.run(probe())

        assert state.solved, "info-processing lab banner never flipped (no admin login)"
        assert finding.exploit_status == "succeeded"
        joined = "\n".join(finding.extracted_data)
        assert password in joined, "extracted password missing from evidence"
        assert "ACCOUNT TAKEOVER" in joined
