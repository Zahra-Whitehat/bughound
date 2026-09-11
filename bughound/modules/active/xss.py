"""Reflected XSS detection."""

from __future__ import annotations

import html

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register
from ._util import send_with_param

MARKER = "bhXSS9271"
PROBE = f"<{MARKER}>\"'"


@register
class XssModule(Module):
    name = "xss"
    categories = [Category.XSS]
    passive = False
    aggressive_required = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rt in ctx.request_targets:
            for param in rt.params:
                r = await send_with_param(ctx.client, rt, param, PROBE)
                if not r.ok:
                    continue
                # Reflected unencoded (angle brackets survive) => likely executable.
                if f"<{MARKER}>" in r.text:
                    findings.append(
                        Finding(
                            category=Category.XSS,
                            title=f"Reflected XSS in '{param}'",
                            severity=Severity.HIGH,
                            confidence="confirmed",
                            url=rt.url,
                            description=(
                                f"Input from '{param}' is reflected without HTML-encoding, "
                                "allowing script injection."
                            ),
                            evidence=f"Payload {PROBE!r} reflected as raw HTML (<{MARKER}> present).",
                            request=f"{rt.method} {rt.url} ({param}={PROBE})",
                            response_excerpt=self._excerpt(r.text),
                            remediation="Context-aware output encoding; apply CSP; validate input.",
                            cwe="CWE-79",
                            module=self.name,
                            verified=True,
                        )
                    )
                elif MARKER in r.text and html.escape(PROBE) not in r.text and PROBE not in r.text:
                    findings.append(
                        Finding(
                            category=Category.XSS,
                            title=f"Input reflected (partial) in '{param}'",
                            severity=Severity.LOW,
                            confidence="tentative",
                            url=rt.url,
                            description=f"Input from '{param}' is reflected; encoding of special chars needs review.",
                            evidence=f"Marker {MARKER!r} present in response.",
                            request=f"{rt.method} {rt.url} ({param}={PROBE})",
                            remediation="Verify output encoding for this reflection context.",
                            cwe="CWE-79",
                            module=self.name,
                            verified=False,
                        )
                    )
        return findings

    @staticmethod
    def _excerpt(text: str) -> str:
        idx = text.find(f"<{MARKER}>")
        start = max(0, idx - 80)
        return text[start : idx + 80]
