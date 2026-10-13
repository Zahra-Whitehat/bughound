"""Open redirect detection."""

from __future__ import annotations

from urllib.parse import urlparse

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register

EVIL = "https://bughound-evil.example/"
REDIRECT_PARAM_HINTS = ("url", "redirect", "next", "return", "dest", "continue", "goto", "target")


@register
class OpenRedirectModule(Module):
    name = "open-redirect"
    categories = [Category.OPEN_REDIRECT]
    passive = False
    aggressive_required = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rt in ctx.request_targets:
            for param in rt.params:
                if not any(h in param.lower() for h in REDIRECT_PARAM_HINTS):
                    continue
                params = dict(rt.params)
                params[param] = EVIL
                if rt.method.upper() == "POST":
                    r = await ctx.client.post(rt.url, data=params, follow_redirects=False)
                else:
                    r = await ctx.client.get(rt.url, params=params, follow_redirects=False)
                location = r.headers.get("location", "")
                final_host = urlparse(r.url).hostname or ""
                if location.startswith(EVIL) or "bughound-evil.example" in final_host:
                    findings.append(
                        Finding(
                            category=Category.OPEN_REDIRECT,
                            title=f"Open redirect via '{param}'",
                            severity=Severity.MEDIUM,
                            confidence="confirmed",
                            url=rt.url,
                            description=f"'{param}' redirects to an attacker-controlled external URL.",
                            evidence=f"Set {param}={EVIL} -> Location/final: {location or final_host}",
                            request=f"{rt.method} {rt.url} ({param}={EVIL})",
                            remediation="Redirect only to allowlisted relative paths; reject absolute external URLs.",
                            cwe="CWE-601",
                            module=self.name,
                            verified=True,
                        )
                    )
        return findings
