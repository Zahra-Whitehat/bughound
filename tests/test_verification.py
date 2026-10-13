"""Tests for the false-positive verification layer (bughound.verification)."""

from __future__ import annotations

import pytest

from bughound.models import Category, Finding, Severity
from bughound.verification import (
    Check,
    VerificationOutcome,
    _canary,
    _verdict,
    _record,
    verify_generic,
)


def _finding(category=Category.SQLI, title="Error-based SQL injection in 'q'", url="http://t/x") -> Finding:
    return Finding(
        category=category,
        title=title,
        severity=Severity.CRITICAL,
        url=url,
        module="test",
        verified=True,
        confidence="confirmed",
    )


def test_canary_is_unique_and_prefixed():
    a, b = _canary("xss"), _canary("xss")
    assert a != b
    assert a.startswith("xss")
    assert len(a) == len("xss") + 10


def test_check_dict_shape():
    c = Check("negative-control", True, "no error")
    d = c.as_dict()
    assert d == {"name": "negative-control", "passed": True, "detail": "no error"}


def test_verdict_all_passed_is_low_risk():
    out = VerificationOutcome(checks=[
        Check("negative-control", True, "ok"),
        Check("repeat-consistency", True, "ok"),
    ])
    v = _verdict(out, "error-based SQL injection")
    assert out.risk == "low"
    assert "low" in v.lower() or "passed" in v.lower()
    assert "FAILED" not in v


def test_verdict_failures_raise_risk():
    out = VerificationOutcome(checks=[
        Check("negative-control", False, "boom"),
        Check("repeat-consistency", False, "drift"),
    ])
    v = _verdict(out, "error-based SQL injection")
    assert out.risk == "high"
    assert "FAILED" in v
    assert "unconfirmed" in v.lower()


def test_verdict_single_failure_is_medium():
    out = VerificationOutcome(checks=[Check("negative-control", False, "boom")])
    _verdict(out, "x")
    assert out.risk == "medium"


def test_record_downgrades_verified_finding_on_failure():
    f = _finding()
    out = VerificationOutcome(checks=[
        Check("negative-control", False, "control also triggered it"),
        Check("repeat-consistency", False, "signature not reproducible"),
    ])
    out.verdict = _verdict(out, "error-based SQL injection")
    _record(f, out)
    assert f.fp_risk == "high"
    assert f.verified is False
    assert f.confidence == "tentative"
    assert len(f.verification_checks) == 2


def test_record_keeps_verified_finding_when_all_pass():
    f = _finding()
    out = VerificationOutcome(checks=[Check("negative-control", True, "clean")])
    out.risk = "low"
    out.verdict = _verdict(out, "error-based SQL injection")
    _record(f, out)
    assert f.verified is True
    assert f.fp_risk == "low"
    assert f.verification_checks[0]["passed"] is True


@pytest.mark.asyncio
async def test_verify_generic_records_evidence_check():
    f = _finding(category=Category.LDAP_HEADER_INJECTION, title="CRLF in 'X'", url="http://t/x")
    f.evidence = "some captured evidence"
    out = await verify_generic(None, f, None, None)
    assert any(c.name == "evidence-captured" and c.passed for c in out.checks)
    assert f.fp_risk in ("low", "medium", "high")


@pytest.mark.asyncio
async def test_verify_generic_flags_missing_evidence():
    f = _finding(category=Category.MISCONFIG, title="Misc in 'X'")
    f.evidence = ""
    out = await verify_generic(None, f, None, None)
    assert any(not c.passed for c in out.checks)


def test_markdown_renders_verification_table():
    from bughound.models import ScanConfig, ScanResult, Target
    from bughound.reporting import to_markdown

    f = _finding()
    f.verification_checks = [
        {"name": "negative-control", "passed": True, "detail": "clean"},
        {"name": "repeat-consistency", "passed": False, "detail": "drifted"},
    ]
    f.fp_risk = "medium"
    f.fp_verdict = "1 of 2 checks failed."
    config = ScanConfig(target_url="http://t", aggressive=True)
    result = ScanResult(
        target=Target(url="http://t", scheme="http", host="t", port=80),
        config=config,
        findings=[f],
    )
    md = to_markdown(result)
    assert "#### False-positive analysis" in md
    assert "| negative-control | PASS | clean |" in md
    assert "| repeat-consistency | FAIL | drifted |" in md
    assert "MEDIUM false-positive risk" in md


def test_markdown_exploited_finding_gets_fp_disproof_note():
    from bughound.models import ScanConfig, ScanResult, Target
    from bughound.reporting import to_markdown

    f = _finding()
    f.exploit_status = "succeeded"
    f.exploit_summary = "extracted credentials"
    config = ScanConfig(target_url="http://t", aggressive=True)
    result = ScanResult(
        target=Target(url="http://t", scheme="http", host="t", port=80),
        config=config,
        findings=[f],
    )
    md = to_markdown(result)
    assert "False-positive analysis" in md
    assert "strongest false-positive disproof" in md
