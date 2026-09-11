"""Path traversal / LFI detection."""

from __future__ import annotations

import re

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register
from ._util import send_with_param

PAYLOADS = [
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
    "../../../../../../windows/win.ini",
]
PASSWD_RE = re.compile(r"root:.*:0:0:")
WININI_RE = re.compile(r"\[(extensions|fonts)\]", re.IGNORECASE)


@register
class PathTraversalModule(Module):
    name = "path-traversal"
    categories = [Category.PATH_TRAVERSAL]
    passive = False
    aggressive_required = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rt in ctx.request_targets:
            for param in rt.params:
                for payload in PAYLOADS:
                    r = await send_with_param(ctx.client, rt, param, payload)
                    if not r.ok:
                        continue
                    if PASSWD_RE.search(r.text) or WININI_RE.search(r.text):
                        findings.append(
                            Finding(
                                category=Category.PATH_TRAVERSAL,
                                title=f"Path traversal / LFI in '{param}'",
                                severity=Severity.CRITICAL,
                                confidence="confirmed",
                                url=rt.url,
                                description=f"'{param}' allows reading arbitrary local files via directory traversal.",
                                evidence=f"Payload {payload!r} returned system file contents.",
                                request=f"{rt.method} {rt.url} ({param}={payload})",
                                response_excerpt=r.text[:300],
                                remediation="Resolve and canonicalize paths, enforce an allowlist, never use raw input in file paths.",
                                cwe="CWE-22",
                                module=self.name,
                                verified=True,
                            )
                        )
                        break
        return findings
