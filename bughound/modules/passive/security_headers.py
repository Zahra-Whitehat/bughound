"""Security header and clickjacking checks."""

from __future__ import annotations

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register


@register
class SecurityHeadersModule(Module):
    name = "security-headers"
    categories = [Category.MISCONFIG, Category.CLICKJACKING]
    passive = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        resp = await ctx.client.get(ctx.base_url)
        if not resp.ok:
            return []
        h = resp.headers
        findings: list[Finding] = []

        def missing(header: str) -> bool:
            return header.lower() not in h

        checks = [
            (
                "content-security-policy",
                Category.MISCONFIG,
                Severity.MEDIUM,
                "Missing Content-Security-Policy",
                "No CSP header. CSP is a key defense-in-depth control against XSS and data injection.",
                "Define a restrictive Content-Security-Policy (e.g. default-src 'self').",
                "CWE-693",
            ),
            (
                "strict-transport-security",
                Category.MISCONFIG,
                Severity.MEDIUM,
                "Missing HSTS (Strict-Transport-Security)",
                "No HSTS header, so browsers may downgrade to HTTP and are exposed to SSL-strip attacks.",
                "Send Strict-Transport-Security: max-age=63072000; includeSubDomains; preload over HTTPS.",
                "CWE-319",
            ),
            (
                "x-content-type-options",
                Category.MISCONFIG,
                Severity.LOW,
                "Missing X-Content-Type-Options: nosniff",
                "Without nosniff, browsers may MIME-sniff responses, enabling some XSS vectors.",
                "Send X-Content-Type-Options: nosniff.",
                "CWE-16",
            ),
            (
                "referrer-policy",
                Category.MISCONFIG,
                Severity.INFO,
                "Missing Referrer-Policy",
                "No Referrer-Policy; referrer URLs may leak to third parties.",
                "Send Referrer-Policy: no-referrer or strict-origin-when-cross-origin.",
                "CWE-200",
            ),
        ]
        for header, cat, sev, title, desc, fix, cwe in checks:
            if missing(header):
                findings.append(
                    Finding(
                        category=cat,
                        title=title,
                        severity=sev,
                        confidence="firm",
                        url=resp.url,
                        description=desc,
                        evidence=f"Response headers did not include '{header}'.",
                        remediation=fix,
                        cwe=cwe,
                        module=self.name,
                        verified=True,
                    )
                )

        # Clickjacking: no X-Frame-Options and no frame-ancestors in CSP.
        xfo = h.get("x-frame-options", "")
        csp = h.get("content-security-policy", "")
        if not xfo and "frame-ancestors" not in csp:
            findings.append(
                Finding(
                    category=Category.CLICKJACKING,
                    title="Page can be framed (clickjacking)",
                    severity=Severity.MEDIUM,
                    confidence="firm",
                    url=resp.url,
                    description=(
                        "Neither X-Frame-Options nor a CSP frame-ancestors directive is set, "
                        "so the page can be embedded in a hostile iframe for clickjacking."
                    ),
                    evidence="No X-Frame-Options header and no frame-ancestors in CSP.",
                    remediation="Set X-Frame-Options: DENY (or SAMEORIGIN) and/or CSP frame-ancestors 'none'.",
                    cwe="CWE-1021",
                    module=self.name,
                    verified=True,
                )
            )
        return findings
