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

    # The demo app has no command execution: reflected payloads must NOT be
    # misreported as OS command injection (regression against marker reflection).
    assert Category.CMD_INJECTION not in cats
