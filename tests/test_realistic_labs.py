"""END-TO-END: the FULL pipeline must solve strict Academy lookalikes.

Every test here starts a real HTTP mock (session cookies, per-session CSRF,
required form fields, redirects, sibling exploit server, victim bot), runs
``run_scan`` -- crawl, recon, detection, exploit, chain AND solve phases --
and asserts the mock's own solved banner flipped. No finding is pre-seeded
anywhere: if detection misses the bug the ladder must still drive the
objective from the lab title alone, exactly like the real platform.
"""

from __future__ import annotations

import asyncio

from mock_academy import (
    build_2fa_lab,
    build_blind_conditional_lab,
    build_cookie_role_lab,
    build_cookie_steal_lab,
    build_robots_admin_lab,
    build_ssrf_lab,
    build_stored_xss_lab,
    lab_server,
    start_background_bots,
)

from bughound.authorization import Scope
from bughound.engine import run_scan
from bughound.models import Category, ScanConfig


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


def _scope() -> Scope:
    return Scope(allowed_hosts=["127.0.0.1"], note="e2e mock lab")


def _run(base: str):
    return asyncio.run(run_scan(_config(base), _scope(), confirmed=True, progress=lambda m: None))


def test_e2e_stored_xss_lab_solves():
    app, state = build_stored_xss_lab()
    with lab_server(app) as base:
        result = _run(base)
        assert state.solved, "stored-XSS lab banner never flipped"
        assert result.objective and result.objective.get("solved_after") is True


def test_e2e_2fa_simple_bypass_solves():
    app, state = build_2fa_lab()
    with lab_server(app) as base:
        result = _run(base)
        assert state.solved, "2FA bypass lab banner never flipped"
        assert result.objective and result.objective.get("solved_after") is True


def test_e2e_ssrf_local_admin_solves():
    app, state = build_ssrf_lab()
    with lab_server(app) as base:
        result = _run(base)
        assert state.solved, "SSRF lab banner never flipped"
        assert result.objective and result.objective.get("solved_after") is True


def test_e2e_cookie_role_flip_solves():
    app, state = build_cookie_role_lab()
    with lab_server(app) as base:
        result = _run(base)
        assert state.solved, "cookie role flip lab banner never flipped"
        assert result.objective and result.objective.get("solved_after") is True


def test_e2e_robots_admin_lab_solves():
    app, state = build_robots_admin_lab()
    with lab_server(app) as base:
        result = _run(base)
        assert state.solved, "robots-disclosed admin lab banner never flipped"
        assert result.objective and result.objective.get("solved_after") is True


def test_e2e_blind_conditional_responses_lab_solves():
    """The v1.1.x failure family: 'Blind SQL injection with conditional
    responses'. The oracle lives in the TrackingId cookie and only flips a
    small 'Welcome back' block inside a large shop page (similarity-based
    detection cannot see it). The pipeline must detect it via the chunk
    differential, calibrate the oracle, binary-search the administrator
    password, log in, and flip the banner -- unattended."""
    app, state, _password = build_blind_conditional_lab()
    with lab_server(app) as base:
        result = _run(base)
        assert state.solved, "blind-SQLi conditional-responses lab banner never flipped"
        assert result.objective and result.objective.get("solved_after") is True
        # the exploited finding must be the cookie injection point
        cookie_sqli = [
            f for f in result.findings
            if f.category == Category.SQLI and "cookie:TrackingId" in f.title
        ]
        assert cookie_sqli, "no cookie:TrackingId SQLi finding recorded"


def test_e2e_cookie_steal_via_exploit_server_solves():
    lab, exploit, state, exploit_base_box, bots = build_cookie_steal_lab()
    with lab_server(lab) as lab_base, lab_server(exploit) as expl_base:
        exploit_base_box["base"] = expl_base
        bot_thread = start_background_bots(bots, lab_base, expl_base)
        try:
            result = _run(lab_base)
            assert state.solved, "cookie-steal lab banner never flipped"
            assert result.objective and result.objective.get("solved_after") is True
        finally:
            # stop the bot loop
            state.solved = True
            bot_thread.join(timeout=6)
