"""v1.2.0 regression tests: polarity-agnostic boolean oracles.

Covers the 'Blind SQL injection with conditional responses' failure family:
the TRUE payload ADDS content ("Welcome back") the baseline lacks, which the
1.1.x similarity rule (true~base > false~base) read as "no differential".
"""

from __future__ import annotations

import asyncio

import pytest

from bughound.models import Category, Finding, ScanResult, Severity
from bughound.objectives import build_ladder
from bughound.modules.active.sqli import SqliModule, _similarity


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _finding(category: Category, title: str, url: str) -> Finding:
    return Finding(
        category=category, title=title, severity=Severity.HIGH,
        confidence="firm", url=url, description="", evidence="",
    )


def _result(*findings: Finding) -> ScanResult:
    from bughound.models import ScanConfig, Target

    cfg = ScanConfig(target_url="http://t/")
    res = ScanResult(config=cfg, target=Target(host="t", url="http://t/"))
    for f in findings:
        res.add(f)
    return res


# ---------------------------------------------------------------------------
# detection polarity
# ---------------------------------------------------------------------------

def test_boolean_detection_accepts_added_content_polarity():
    """TRUE page = baseline + extra block; FALSE page = baseline exactly.

    This is the TrackingId/conditional-responses orientation that 1.1.x
    missed: sim(true, base) < sim(false, base).
    """
    base = "<html>shop<body>products</body></html>"
    true_page = "<html>shop<body>Welcome back!products</body></html>"
    false_page = base

    true_vs_base = _similarity(true_page, base)
    false_vs_base = _similarity(false_page, base)
    true_vs_false = _similarity(true_page, false_page)

    # old rule fails on this polarity...
    assert not (true_vs_base > false_vs_base)
    # ...but the page pair IS a genuine differential
    assert true_vs_false < 0.98
    assert max(true_vs_base, false_vs_base) >= 0.98


def test_boolean_detection_rule_symmetric_reference():
    """The polarity-agnostic rule keeps accepting the classic orientation."""
    base = "<html>shop<body>products</body></html>"
    true_page = base                    # TRUE reproduces baseline
    false_page = "<html>error</html>"   # FALSE hides everything

    t_b, f_b = _similarity(true_page, base), _similarity(false_page, base)
    assert _similarity(true_page, false_page) < 0.98
    assert max(t_b, f_b) >= 0.98  # exactly one side reproduces the baseline


# ---------------------------------------------------------------------------
# ladder wiring
# ---------------------------------------------------------------------------

def test_blind_sqli_titles_get_cookie_oracle_strategy_first():
    ladder = build_ladder("Blind SQL injection with conditional responses", None)
    assert ladder[0].name == "sqli-blind-cookie-oracle"
    assert "sqli-extraction-login" in [s.name for s in ladder[:4]]


def test_blind_sqli_variant_titles_match():
    for title in (
        "Blind SQL injection with conditional errors",
        "Blind SQL injection with time delays",
        "Blind SQL injection with time delays and information retrieval",
        "Visible error-based SQL injection",  # no "blind" -> not matched
    ):
        ladder = build_ladder(title, None)
        first = ladder[0].name
        if "blind" in title.lower():
            assert first == "sqli-blind-cookie-oracle", title
        else:
            assert first != "sqli-blind-cookie-oracle", title


def test_union_labs_still_prefer_union_hint_strategy():
    ladder = build_ladder("SQL injection UNION attack, finding a column containing text", None)
    assert ladder[0].name == "sqli-union-hint-objective"


# ---------------------------------------------------------------------------
# chunk-level differential (small-answer / large-page oracles)
# ---------------------------------------------------------------------------

_LARGE_SHOP = (
    "<html><head><title>Blind SQL injection with conditional responses</title></head>"
    "<body><div id=academyLabHeader></div>"
    "<a href='/login'>Login</a>{welcome}"
    + "".join(
        f"<section class=product><h3>Gadget {i}</h3><p>$19.9{i}</p></section>"
        for i in range(1, 41)
    )
    + "</body></html>"
)


def test_chunk_differential_detects_tiny_welcome_block():
    """Whole-page similarity of the two answer pages stays >= 0.98 (one small
    block inside a large shop page) yet the chunk set differs."""
    from bughound.modules.active.sqli import _chunk_differential, _similarity

    true_page = _LARGE_SHOP.format(welcome="<p>Welcome back!</p>")
    false_page = _LARGE_SHOP.format(welcome="")
    assert _similarity(true_page, false_page) >= 0.98  # similarity is blind here
    assert _chunk_differential(false_page, true_page, false_page) is True


def test_chunk_differential_rejects_payload_echo():
    from bughound.modules.active.sqli import _chunk_differential

    base = "<html><body>products</body></html>"
    true_page = "<html><body>products ' AND '1'='1</body></html>"
    false_page = "<html><body>products ' AND '1'='2</body></html>"
    assert _chunk_differential(base, true_page, false_page) is False


def test_chunk_differential_rejects_nondeterministic_pages():
    """A baseline that matches NEITHER payload page (rotating content) must
    never produce a signal."""
    from bughound.modules.active.sqli import _chunk_differential

    base = "<html><body>nonce-A products</body></html>"
    true_page = "<html><body>nonce-B products</body></html>"
    false_page = "<html><body>nonce-C products</body></html>"
    assert _chunk_differential(base, true_page, false_page) is False


# ---------------------------------------------------------------------------
# oracle calibration (unit level, mocked client)
# ---------------------------------------------------------------------------

class _Resp:
    def __init__(self, text: str, status: int = 200):
        self.text = text
        self.status = status
        self.ok = True
        self.elapsed = 0.1


class _Client:
    """Minimal client double: routes cookie-injected requests to a canned
    oracle function."""

    def __init__(self, oracle):
        self._oracle = oracle
        self.jar = {"TrackingId": "abc", "session": "sess-1"}

    def jar_cookies(self):
        return dict(self.jar)

    def set_cookie(self, name, value):
        self.jar[name] = value


@pytest.mark.asyncio
async def test_calibrate_accepts_added_content_polarity(monkeypatch):
    from bughound.exploits.sqli import calibrate_boolean_oracle
    from bughound.modules.base import RequestTarget, ScanContext

    def page_for(value: str) -> str:
        base = "<html>shop<body>products</body></html>"
        if "' AND '1'='1" in value:
            return base.replace("products", "Welcome back!products")
        if "' AND '1'='2" in value:
            return base
        return base

    async def fake_send(client, rt, param, value):
        return _Resp(page_for(value))

    monkeypatch.setattr("bughound.exploits.sqli.send_with_param", fake_send)

    ctx = ScanContext(client=_Client(page_for), config=None, target=None, base_url="http://t/")
    rt = RequestTarget(url="http://t/", method="GET", params={})
    oracle = await calibrate_boolean_oracle(ctx, rt, "cookie:TrackingId")
    assert oracle is not None
    assert "Welcome back" in oracle.true_text
    assert "Welcome back" not in oracle.false_text


@pytest.mark.asyncio
async def test_calibrate_rejects_no_differential(monkeypatch):
    from bughound.exploits.sqli import calibrate_boolean_oracle
    from bughound.modules.base import RequestTarget, ScanContext

    async def fake_send(client, rt, param, value):
        return _Resp("<html>same</html>")

    monkeypatch.setattr("bughound.exploits.sqli.send_with_param", fake_send)

    ctx = ScanContext(client=_Client(None), config=None, target=None, base_url="http://t/")
    rt = RequestTarget(url="http://t/", method="GET", params={})
    assert await calibrate_boolean_oracle(ctx, rt, "cookie:TrackingId") is None


@pytest.mark.asyncio
async def test_ask_judges_by_reference_not_baseline(monkeypatch):
    """The decisive 1.1.x bug: answers were compared to the baseline, which
    inverts added-content oracles. Answers must now be judged against the
    calibrated references."""
    from bughound.exploits.sqli import BooleanOracle, _ask
    from bughound.modules.base import RequestTarget, ScanContext

    base = "<html>shop<body>products</body></html>"
    true_ref = base.replace("products", "Welcome back!products")
    false_ref = base

    state = {"cond": True}

    async def fake_send(client, rt, param, value):
        # emulate a working oracle: condition TRUE -> welcome page
        t = "ABCD" in value or "1=1" in value
        if "length(" in value or "ASCII(" in value:
            t = state["cond"]
        return _Resp(true_ref if t else false_ref)

    monkeypatch.setattr("bughound.exploits.sqli.send_with_param", fake_send)

    ctx = ScanContext(client=_Client(None), config=None, target=None, base_url="http://t/")
    rt = RequestTarget(url="http://t/", method="GET", params={})
    oracle = BooleanOracle(rt=rt, param="cookie:TrackingId", true_text=true_ref, false_text=false_ref)
    budget = [10]

    # baseline page == false reference: on the OLD baseline-comparison rule
    # a TRUE answer (which differs from baseline) read as False. Must be True.
    state["cond"] = True
    assert await _ask(ctx, oracle, "length((SELECT 1))>0", budget) is True
    state["cond"] = False
    assert await _ask(ctx, oracle, "length((SELECT 1))>0", budget) is False
