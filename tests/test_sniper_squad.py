"""Tests for the 0.7 sniper-squad layer: modes, squads, planner, diff, reporting.

Unit-level (no network) except where noted; these validate the Sn1per and
Bug-Bounty-Agents integration seams in isolation.
"""

from __future__ import annotations

import json

from bughound.agents.planner import build_attack_plan
from bughound.agents.squads import module_squad, split_by_phase
from bughound.diff import diff_files, diff_markdown, diff_reports
from bughound.models import (
    Category,
    Finding,
    ScanConfig,
    ScanResult,
    Severity,
    Target,
)
from bughound.modes import KNOWN_MODES, apply_mode, mode_profile
from bughound.modules.base import Module
from bughound.reporting import to_json, to_markdown

# ---------------------------------------------------------------------------
# Modes (Sn1per)
# ---------------------------------------------------------------------------


def _config() -> ScanConfig:
    return ScanConfig(target_url="http://127.0.0.1:8081/")


def test_mode_stealth_is_passive_and_slow():
    cfg = _config()
    cfg.aggressive = True  # even a previously-aggressive config is calmed
    profile = apply_mode(cfg, "stealth")
    assert profile is not None
    assert cfg.aggressive is False
    assert cfg.exploit is False
    assert cfg.bruteforce is False
    assert cfg.concurrency <= 2
    assert cfg.use_external_tools is False


def test_mode_normal_detects_without_exploit():
    cfg = _config()
    apply_mode(cfg, "normal")
    assert cfg.aggressive is True
    assert cfg.exploit is False
    assert cfg.bruteforce is False


def test_mode_aggressive_is_full_pipeline():
    cfg = _config()
    apply_mode(cfg, "aggressive")
    assert cfg.aggressive is True
    assert cfg.exploit is True
    assert cfg.bruteforce is False


def test_mode_nuke_enables_credential_checks():
    cfg = _config()
    cfg.use_external_tools = False
    apply_mode(cfg, "nuke")
    assert cfg.aggressive and cfg.exploit and cfg.bruteforce
    assert cfg.use_external_tools is True


def test_unknown_mode_is_ignored():
    cfg = _config()
    assert apply_mode(cfg, "does-not-exist") is None
    assert apply_mode(cfg, "") is None
    assert cfg.mode == ""
    assert set(KNOWN_MODES) == {"stealth", "normal", "aggressive", "nuke"}
    assert mode_profile(None) is None


# ---------------------------------------------------------------------------
# Squads (Bug-Bounty-Agents swarm orchestration)
# ---------------------------------------------------------------------------


class _Mod(Module):
    def __init__(self, name: str, passive: bool):
        self.name = name
        self.passive = passive

    async def run(self, ctx):  # pragma: no cover
        return []


def test_split_by_phase_recon_first():
    recon = _Mod("dns-recon", passive=True)
    sqli = _Mod("sqli", passive=False)
    cookies = _Mod("cookies", passive=True)
    jwt = _Mod("jwt-attacks", passive=False)
    phase1, phase2 = split_by_phase([sqli, recon, jwt, cookies])
    assert [m.name for m in phase1] == ["dns-recon", "cookies"]
    assert [m.name for m in phase2] == ["sqli", "jwt-attacks"]


def test_unlisted_module_falls_back_but_still_runs():
    recon, unknown_active = split_by_phase([_Mod("brand-new-module", passive=False)])
    assert recon == []
    assert [m.name for m in unknown_active] == ["brand-new-module"]
    assert module_squad("brand-new-module") == "ACCESS SQUAD"
    assert module_squad("brand-new-passive", passive=True) == "CONFIG SQUAD"
    assert module_squad("sqli") == "INJECTION SQUAD"
    assert module_squad("dns-recon") == "RECON SQUAD"


# ---------------------------------------------------------------------------
# Planner (attack-planner persona)
# ---------------------------------------------------------------------------


def test_planner_focus_areas_and_waf():
    plan = build_attack_plan(
        {
            "admin_paths": ["/admin", "/phpmyadmin"],
            "tech_stack": {"CMS": ["WordPress"]},
            "waf": "Cloudflare",
            "subdomains": ["api.example.com"],
            "api_docs": ["/openapi.json"],
        },
        aggressive=True,
    )
    areas = {f["area"] for f in plan["focus_areas"]}
    assert "admin panel exposed" in areas
    assert "API documentation exposed" in areas
    assert plan["waf"]["name"] == "Cloudflare"
    assert "Cloudflare" in "".join(plan["waf"]["advice"])
    assert any(n.startswith("[WordPress]") for n in plan["tech_notes"])
    assert plan["surface_stats"]["subdomains"] == 1


def test_planner_empty_recon_is_quiet():
    plan = build_attack_plan({}, aggressive=False)
    assert plan["focus_areas"] == []
    assert plan["waf"] == {}
    assert any("Passive mode" in h for h in plan["hints"])


# ---------------------------------------------------------------------------
# Diff (continuous monitoring)
# ---------------------------------------------------------------------------


def _result(findings: list[Finding], recon: dict | None = None) -> ScanResult:
    r = ScanResult(
        target=Target(url="http://127.0.0.1:8081/", scheme="http", host="127.0.0.1", port=8081),
        config=ScanConfig(target_url="http://127.0.0.1:8081/"),
    )
    for f in findings:
        r.add(f)
    if recon:
        r.recon.update(recon)
    return r


def _finding(title: str, sev: Severity = Severity.MEDIUM,
             category: Category = Category.MISCONFIG) -> Finding:
    return Finding(
        category=category, title=title, severity=sev, url="http://127.0.0.1:8081/x",
        description="d", module="test",
    )


def test_diff_new_and_resolved_findings(tmp_path):
    old = _result([_finding("old-stays"), _finding("old-resolved")])
    new = _result([_finding("old-stays"), _finding("new-critical", Severity.CRITICAL)])
    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    old_path.write_text(to_json(old))
    new_path.write_text(to_json(new))

    d = diff_files(str(old_path), str(new_path))
    titles_new = {f["title"] for f in d.new_findings}
    titles_gone = {f["title"] for f in d.resolved_findings}
    assert titles_new == {"new-critical"}
    assert titles_gone == {"old-resolved"}
    assert d.host == "127.0.0.1"

    md = diff_markdown(d, str(old_path), str(new_path))
    assert "New findings (1)" in md
    assert "new-critical" in md
    assert "Resolved findings (1)" in md
    assert "old-resolved" in md


def test_diff_now_exploited_and_recon_changes(tmp_path):
    f1 = _finding("sqli-finding")
    old = _result([f1])
    old.recon.update({"subdomains": ["a.example.com"]})

    f2 = _finding("sqli-finding")
    f2.exploit_status = "succeeded"
    new = _result([f2])
    new.recon.update({"subdomains": ["a.example.com", "b.example.com"]})

    d = diff_reports(json.loads(to_json(old)), json.loads(to_json(new)))
    assert [f["title"] for f in d.now_exploited] == ["sqli-finding"]
    assert d.recon_added.get("subdomains") == ["b.example.com"]
    assert not d.recon_removed
    assert d.has_changes


def test_diff_no_changes(tmp_path):
    old = _result([_finding("same")])
    new = _result([_finding("same")])
    d = diff_reports(json.loads(to_json(old)), json.loads(to_json(new)))
    assert not d.has_changes
    md = diff_markdown(d)
    assert "No changes" in md


# ---------------------------------------------------------------------------
# Reporting: plan / chains / bounty drafts
# ---------------------------------------------------------------------------


def test_report_renders_plan_chains_and_bounty():
    result = _result([_finding("big-critical", Severity.CRITICAL, Category.SQLI)])
    result.plan = build_attack_plan(
        {"admin_paths": ["/admin"], "waf": "Cloudflare"}, aggressive=True
    )
    # Build a chain finding.
    from bughound.agents.exploit_chainer import _add_chain

    ingredient = _finding("traversal-in-name", Severity.HIGH, Category.PATH_TRAVERSAL)
    result.add(ingredient)
    chain = _add_chain(
        result,
        label="traversal-to-credentials",
        constituents=[ingredient],
        category=Category.INFO_DISCLOSURE,
        severity=Severity.HIGH,
        title="Chained: path traversal exposes credential-bearing configuration",
        url="http://127.0.0.1:8081/file",
        description="desc",
        evidence="ev",
        impact="imp",
        remediation="fix",
        verified=True,
        confidence="confirmed",
    )
    assert chain.chain_of == [ingredient.fingerprint]

    md = to_markdown(result)
    assert "## Attack plan" in md
    assert "Cloudflare" in md
    assert "## Attack chains" in md
    assert "`traversal-to-credentials`" in md
    assert "**Chain narrative.**" in md
    assert "#### Bounty submission draft" in md  # for the CRITICAL finding
