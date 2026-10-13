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
async def test_full_scan_finds_vulns(server):
    config = ScanConfig(target_url=server, aggressive=True, use_external_tools=False, max_urls=20)
    scope = Scope(allowed_hosts=["127.0.0.1"])
    result = await run_scan(config, scope, confirmed=True)

    cats = {f.category for f in result.findings}
    assert Category.XSS in cats
    assert Category.SQLI in cats
    assert Category.PATH_TRAVERSAL in cats
    assert Category.OPEN_REDIRECT in cats
    assert Category.CRYPTO in cats  # hardcoded secrets
    assert Category.MISCONFIG in cats  # missing headers
    assert Category.SESSION in cats  # cookie flags

    verified = [f for f in result.findings if f.verified]
    assert verified, "expected at least one verified finding"

    # The demo app now ships a genuinely vulnerable /ping endpoint (real
    # shell interpolation), so OS command injection IS expected -- the old
    # "no CMD_INJECTION" regression guarded against marker reflection on a
    # non-vulnerable app, which no longer matches the demo.
    assert Category.CMD_INJECTION in cats
    cmd = next(f for f in result.findings if f.category == Category.CMD_INJECTION)
    assert cmd.verified, "command injection should be output-verified"


@pytest.mark.asyncio
async def test_exploit_phase_proves_impact(server):
    """The exploit phase upgrades detection findings into demonstrated impact."""
    from bughound.models import Severity

    config = ScanConfig(
        target_url=server, aggressive=True, exploit=True,
        use_external_tools=False, max_urls=20,
    )
    scope = Scope(allowed_hosts=["127.0.0.1"])
    result = await run_scan(config, scope, confirmed=True)

    exploited = [f for f in result.findings if f.exploit_status == "succeeded"]
    assert exploited, "expected at least one finding to be exploited end-to-end"
    assert result.stats.get("exploited", 0) == len(exploited)

    by_title_kw = {}
    for f in exploited:
        by_title_kw.setdefault(f.category, []).append(f)

    # SQLi: UNION extraction must yield the sqlite version + table names.
    sqli = next((f for f in exploited if f.category == Category.SQLI and f.extracted_data), None)
    assert sqli is not None, "SQLi should be proven with extracted data"
    assert any("sqlite" in str(d).lower() for d in sqli.extracted_data)
    assert any("products" in str(d) for d in sqli.extracted_data), "table enumeration proof missing"
    assert sqli.poc_curl.startswith("curl")
    assert "Host:" in sqli.raw_request

    # RCE: command output capture must include the uid line.
    rce = next((f for f in exploited if f.category in (Category.CMD_INJECTION, Category.RCE)), None)
    assert rce is not None, "RCE should be proven with captured command output"
    assert any("uid=" in str(d) for d in rce.extracted_data), "uid capture missing"

    # Traversal: real file contents extracted.
    trav = next((f for f in exploited if f.category == Category.PATH_TRAVERSAL), None)
    assert trav is not None
    assert any("/etc/passwd" in str(d) for d in trav.extracted_data)

    # SSRF: loopback proof upgraded the finding to verified.
    ssrf = next((f for f in result.findings if f.category == Category.SSRF), None)
    assert ssrf is not None
    assert ssrf.exploit_status == "succeeded"
    assert ssrf.verified, "SSRF loopback proof should upgrade verification"

    # NoSQLi: authentication bypass proven.
    nosql = next((f for f in result.findings if f.category == Category.NOSQLI), None)
    assert nosql is not None
    assert nosql.exploit_status == "succeeded"
    assert nosql.verified

    # XSS: executable payload survival proven.
    xss = next((f for f in exploited if f.category == Category.XSS), None)
    assert xss is not None, "XSS should be proven with surviving executable payloads"
    assert any("<script>" in str(d) or "onerror" in str(d) for d in xss.extracted_data)

    # Severity floor: a proven data-extraction path is critical.
    assert sqli.severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_no_exploit_flag_leaves_findings_untouched(server):
    """--no-exploit (exploit=False) keeps the exploit phase fully off."""
    config = ScanConfig(
        target_url=server, aggressive=True, exploit=False,
        use_external_tools=False, max_urls=20,
    )
    scope = Scope(allowed_hosts=["127.0.0.1"])
    result = await run_scan(config, scope, confirmed=True)
    assert result.findings
    assert all(f.exploit_status == "not_attempted" for f in result.findings)
