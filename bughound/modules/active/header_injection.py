"""CRLF / HTTP response header injection detection."""

from __future__ import annotations

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register
from ._util import send_with_param

MARKER = "bhcrlf"
PAYLOAD = f"test%0d%0aX-Bughound-Injected:{MARKER}"


@register
class HeaderInjectionModule(Module):
    name = "header-injection"
    categories = [Category.LDAP_HEADER_INJECTION]
    passive = False
    aggressive_required = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rt in ctx.request_targets:
            for param in rt.params:
                r = await send_with_param(ctx.client, rt, param, PAYLOAD)
                if not r.ok:
                    continue
                if r.headers.get("x-bughound-injected") == MARKER:
                    findings.append(
                        Finding(
                            category=Category.LDAP_HEADER_INJECTION,
                            title=f"HTTP header (CRLF) injection via '{param}'",
                            severity=Severity.HIGH,
                            confidence="confirmed",
                            url=rt.url,
                            description=f"CRLF sequences in '{param}' are reflected into response headers.",
                            evidence=f"Injected header X-Bughound-Injected:{MARKER} appeared in the response.",
                            request=f"{rt.method} {rt.url} ({param}={PAYLOAD})",
                            remediation="Strip CR/LF from values used in headers; use framework-safe header APIs.",
                            cwe="CWE-113",
                            module=self.name,
                            verified=True,
                        )
                    )
        return findings
