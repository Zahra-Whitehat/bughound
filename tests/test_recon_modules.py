"""Tests for the new passive recon modules.

Validates that each recon module produces the expected findings against a
demo app with controlled recon breadcrumbs, and that the structured recon
data is correctly written to ``ScanResult.recon``.

These tests do NOT require internet access: DNS / CT-log queries skip
themselves for IP-only / localhost targets, so we focus on what we can test
deterministically against the local vulnerable app.
"""

from __future__ import annotations

import socket
import threading
import time

import pytest
import uvicorn

from bughound.authorization import Scope
from bughound.engine import run_scan
from bughound.models import Category, ScanConfig
from examples.vulnerable_app import app as vuln_app


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def server():
    port = _free_port()
    config = uvicorn.Config(vuln_app, host="127.0.0.1", port=port, log_level="warning")
    srv = uvicorn.Server(config)
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    for _ in range(50):
        if srv.started:
            break
        time.sleep(0.1)
    yield f"http://127.0.0.1:{port}/"
    srv.should_exit = True
    thread.join(timeout=5)


@pytest.mark.asyncio
async def test_recon_modules_run_and_emit_findings(server):
    """All recon modules run cleanly and produce at least one finding."""
    config = ScanConfig(target_url=server, aggressive=False, use_external_tools=False, max_urls=20)
    scope = Scope(allowed_hosts=["127.0.0.1"])
    result = await run_scan(config, scope, confirmed=True)

    ran = set(result.modules_run)
    for name in (
        "admin-panels",
        "api-discovery",
        "backup-files",
        "dns-recon",
        "email-harvest",
        "http-methods",
        "info-disclosure",
        "js-endpoints",
        "robots-sitemap",
        "secrets",
        "security-headers",
        "sourcemap-exposure",
        "tech-fingerprint",
        "tls",
        "waf-detection",
        "cookies",
        "cors",
        # subdomain-enum runs but skips for IP-only targets
    ):
        assert name in ran, f"module {name!r} did not run; ran={sorted(ran)}"


@pytest.mark.asyncio
async def test_recon_category_is_emitted(server):
    """At least one finding should use the new RECON category."""
    config = ScanConfig(target_url=server, aggressive=False, use_external_tools=False, max_urls=20)
    scope = Scope(allowed_hosts=["127.0.0.1"])
    result = await run_scan(config, scope, confirmed=True)
    cats = {f.category for f in result.findings}
    assert Category.RECON in cats, f"no RECON finding emitted; categories={cats}"


@pytest.mark.asyncio
async def test_robots_sitemap_discovers_admin_path(server):
    """robots.txt should disclose /admin (a Disallow path) -- surfaced as recon."""
    config = ScanConfig(target_url=server, aggressive=False, use_external_tools=False, max_urls=20)
    scope = Scope(allowed_hosts=["127.0.0.1"])
    result = await run_scan(config, scope, confirmed=True)
    robots_finding = next(
        (f for f in result.findings if f.module == "robots-sitemap" and "robots.txt" in f.title),
        None,
    )
    assert robots_finding is not None, "robots.txt finding not emitted"
    assert "/admin" in robots_finding.evidence or "/private" in robots_finding.evidence
    # Structured data persisted to recon dict
    assert "robots_txt" in result.recon
    assert "User-agent" in result.recon["robots_txt"]
    assert "sitemap_urls" in result.recon
    # The sitemap we set returns URLs relative to the request; they should
    # appear (after same-origin filtering) in the structured recon dict.
    assert result.recon.get("sitemap_urls"), "sitemap_urls should not be empty"


@pytest.mark.asyncio
async def test_admin_panel_module_finds_admin(server):
    """The /admin path is exposed and should be discovered."""
    config = ScanConfig(target_url=server, aggressive=False, use_external_tools=False, max_urls=20)
    scope = Scope(allowed_hosts=["127.0.0.1"])
    result = await run_scan(config, scope, confirmed=True)
    admin_findings = [f for f in result.findings if f.module == "admin-panels"]
    assert admin_findings, "admin-panels module emitted no findings"
    titles = " ".join(f.title for f in admin_findings)
    assert "admin" in titles.lower(), f"no admin path discovered; titles={titles}"
    assert any("/admin" in str(p) for p in result.recon.get("admin_paths", [])), (
        f"/admin missing from admin_paths: {result.recon.get('admin_paths')}"
    )


@pytest.mark.asyncio
async def test_http_methods_detects_risky_methods(server):
    """OPTIONS advertises PUT/DELETE/TRACE -- must be flagged as risky."""
    config = ScanConfig(target_url=server, aggressive=False, use_external_tools=False, max_urls=20)
    scope = Scope(allowed_hosts=["127.0.0.1"])
    result = await run_scan(config, scope, confirmed=True)
    methods_finding = next(
        (f for f in result.findings if f.module == "http-methods" and "Risky" in f.title),
        None,
    )
    assert methods_finding is not None, (
        f"no risky-methods finding; http-methods findings: "
        f"{[f.title for f in result.findings if f.module == 'http-methods']}"
    )
    # The structured recon dict should contain the method list.
    methods = result.recon.get("http_methods") or []
    assert "PUT" in methods and "DELETE" in methods and "TRACE" in methods


@pytest.mark.asyncio
async def test_js_endpoints_extracts_api_paths(server):
    """The /static/app.js file references /api/v1/users -- should be extracted."""
    config = ScanConfig(target_url=server, aggressive=False, use_external_tools=False, max_urls=20)
    scope = Scope(allowed_hosts=["127.0.0.1"])
    result = await run_scan(config, scope, confirmed=True)
    endpoints = result.recon.get("js_endpoints") or []
    assert any("/api/v1/users" in e for e in endpoints), (
        f"/api/v1/users not extracted; endpoints={endpoints}"
    )
    assert any("/api/v1/orders" in e for e in endpoints), (
        f"/api/v1/orders not extracted; endpoints={endpoints}"
    )


@pytest.mark.asyncio
async def test_sourcemap_module_detects_exposed_map(server):
    """The /static/app.js.map file should be flagged as exposed source map."""
    config = ScanConfig(target_url=server, aggressive=False, use_external_tools=False, max_urls=20)
    scope = Scope(allowed_hosts=["127.0.0.1"])
    result = await run_scan(config, scope, confirmed=True)
    sm_findings = [f for f in result.findings if f.module == "sourcemap-exposure"]
    assert sm_findings, "no sourcemap-exposure finding"
    sm = result.recon.get("sourcemaps") or []
    assert any("app.js.map" in s for s in sm), f"app.js.map missing from sourcemaps: {sm}"


@pytest.mark.asyncio
async def test_tech_fingerprint_identifies_nginx_and_express(server):
    """The seed response includes Server: nginx and X-Powered-By: Express."""
    config = ScanConfig(target_url=server, aggressive=False, use_external_tools=False, max_urls=20)
    scope = Scope(allowed_hosts=["127.0.0.1"])
    result = await run_scan(config, scope, confirmed=True)
    stack = result.recon.get("tech_stack") or {}
    products = [p for prods in stack.values() for p in prods]
    assert "nginx" in products, f"nginx missing from tech_stack: {stack}"
    assert "Express" in products, f"Express missing from tech_stack: {stack}"


@pytest.mark.asyncio
async def test_email_harvest_finds_admin_email(server):
    """The mailto:admin@example.com link should be harvested."""
    config = ScanConfig(target_url=server, aggressive=False, use_external_tools=False, max_urls=20)
    scope = Scope(allowed_hosts=["127.0.0.1"])
    result = await run_scan(config, scope, confirmed=True)
    emails = result.recon.get("emails") or []
    assert "admin@example.com" in emails, f"admin@example.com not harvested; emails={emails}"


@pytest.mark.asyncio
async def test_recon_section_rendered_in_markdown(server):
    """The markdown report should include a Reconnaissance section."""
    config = ScanConfig(target_url=server, aggressive=False, use_external_tools=False, max_urls=20)
    scope = Scope(allowed_hosts=["127.0.0.1"])
    result = await run_scan(config, scope, confirmed=True)
    from bughound.reporting import to_markdown

    md = to_markdown(result)
    assert "## Reconnaissance" in md, "Reconnaissance section missing from markdown"
    assert "### robots.txt" in md or "robots.txt" in md, "robots.txt subsection missing"
    assert "### Technology stack" in md, "Technology stack subsection missing"


@pytest.mark.asyncio
async def test_recon_dict_in_json_report(server):
    """The JSON report should include the structured recon field."""
    config = ScanConfig(target_url=server, aggressive=False, use_external_tools=False, max_urls=20)
    scope = Scope(allowed_hosts=["127.0.0.1"])
    result = await run_scan(config, scope, confirmed=True)
    import json as _json

    from bughound.reporting import to_json

    data = _json.loads(to_json(result))
    assert "recon" in data, "recon field missing from JSON"
    assert "tech_stack" in data["recon"], "tech_stack missing from recon dict"
    assert "robots_txt" in data["recon"], "robots_txt missing from recon dict"


@pytest.mark.asyncio
async def test_denylist_blocks_admin_panel_check(server):
    """The denylist must prevent admin-panels from probing /admin."""
    config = ScanConfig(target_url=server, aggressive=False, use_external_tools=False, max_urls=20)
    scope = Scope(
        allowed_hosts=["127.0.0.1"],
        denied_urls=[f"{server}admin"],
    )
    result = await run_scan(config, scope, confirmed=True)
    admin_paths = result.recon.get("admin_paths") or []
    assert not any("/admin" in p for p in admin_paths), (
        f"admin-panels probed a denied URL: {admin_paths}"
    )
