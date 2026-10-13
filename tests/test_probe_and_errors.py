"""Tests for the new pre-flight probe and error-reporting behaviour.

These verify the fix for the silent "0 URLs discovered" bug: when the
target is unreachable (timeout, TLS error, connection refused), the scan
must NOT silently run 18 modules against an empty context and produce
zero findings. Instead it must:

  * emit a clear "Target unreachable" error in result.errors
  * NOT run any modules (result.modules_run is empty)
  * return a result quickly (no point waiting through 18 module timeouts)
  * log the failure reason in the progress log
"""

from __future__ import annotations

import socket
import threading
import time

import pytest
import uvicorn

from bughound.authorization import Scope
from bughound.engine import run_scan
from bughound.models import ScanConfig
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
async def test_unreachable_target_aborts_with_clear_error():
    """A non-routable IP must produce a clear error, not a silent 0-finding scan."""
    # 192.0.2.0/24 is TEST-NET-1 (RFC 5737) -- guaranteed non-routable.
    config = ScanConfig(
        target_url="http://192.0.2.1/",
        aggressive=False,
        use_external_tools=False,
        timeout=2.0,  # short timeout so the test runs fast
    )
    scope = Scope(allowed_hosts=["192.0.2.1"])
    progress_log: list[str] = []
    result = await run_scan(
        config, scope, confirmed=True, progress=lambda m: progress_log.append(m)
    )

    # The scan must NOT have run any modules against the empty context.
    assert result.modules_run == [], (
        f"modules ran against unreachable target: {result.modules_run}"
    )
    # The scan must have recorded a clear, actionable error.
    assert result.errors, "no errors recorded for unreachable target"
    assert any("unreachable" in e.lower() or "timeout" in e.lower() or "ConnectError" in e for e in result.errors), (
        f"errors do not mention unreachable/timeout/ConnectError: {result.errors}"
    )
    # The progress log must have surfaced the probe + failure reason.
    log_text = "\n".join(progress_log)
    assert "Probing target" in log_text, f"no probe line in progress log: {progress_log}"
    assert "probe failed" in log_text or "Target unreachable" in log_text, (
        f"no failure reason in progress log: {progress_log}"
    )


@pytest.mark.asyncio
async def test_reachable_target_runs_modules(server):
    """The happy path: a reachable target still runs the modules."""
    config = ScanConfig(
        target_url=server,
        aggressive=False,
        use_external_tools=False,
        max_urls=10,
    )
    scope = Scope(allowed_hosts=["127.0.0.1"])
    progress_log: list[str] = []
    result = await run_scan(
        config, scope, confirmed=True, progress=lambda m: progress_log.append(m)
    )
    assert result.modules_run, "no modules ran against reachable target"
    log_text = "\n".join(progress_log)
    assert "probe OK" in log_text, f"no probe-OK line in log: {progress_log}"

