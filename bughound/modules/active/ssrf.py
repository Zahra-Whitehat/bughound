"""SSRF candidate detection (differential, no OOB)."""

from __future__ import annotations

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register
from ._util import send_with_param

SSRF_PARAM_HINTS = ("url", "uri", "path", "dest", "domain", "callback", "webhook", "fetch", "load", "src", "proxy", "image")
# Benign internal probe (loopback). We never target third-party metadata endpoints.
PROBE = "http://127.0.0.1:1/"


@register
class SsrfModule(Module):
    name = "ssrf"
    categories = [Category.SSRF]
    passive = False
    aggressive_required = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rt in ctx.request_targets:
            for param in rt.params:
                if not any(h in param.lower() for h in SSRF_PARAM_HINTS):
                    continue
                r = await send_with_param(ctx.client, rt, param, PROBE)
                if not r.ok:
                    continue
                low = r.text.lower()
                signs = ["connection refused", "econnrefused", "failed to connect", "could not resolve", "timed out", "no route to host"]
                if any(s in low for s in signs):
                    findings.append(
                        Finding(
                            category=Category.SSRF,
                            title=f"Possible SSRF via '{param}'",
                            severity=Severity.HIGH,
                            confidence="firm",
                            url=rt.url,
                            description=(
                                f"'{param}' appears to trigger a server-side fetch: supplying an internal "
                                "URL produced a connection-level error surfaced from the server."
                            ),
                            evidence=f"Set {param}={PROBE}; response contained a server-side connection error.",
                            request=f"{rt.method} {rt.url} ({param}={PROBE})",
                            remediation="Enforce an egress allowlist, block internal ranges/metadata IPs, resolve+validate hosts.",
                            cwe="CWE-918",
                            module=self.name,
                            verified=False,
                        )
                    )
        return findings
