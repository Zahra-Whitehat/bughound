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
            (
                "permissions-policy",
                Category.MISCONFIG,
                Severity.LOW,
                "Missing Permissions-Policy",
                "No Permissions-Policy; the page (or any iframe embedding it) can use powerful "
                "browser features (camera, microphone, geolocation, payment, USB) by default.",
                "Send Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=().",
                "CWE-732",
            ),
            (
                "cross-origin-embedder-policy",
                Category.MISCONFIG,
                Severity.INFO,
                "Missing Cross-Origin-Embedder-Policy",
                "Without COEP, the document cannot enable cross-origin isolation; shared resources "
                "can be loaded without explicit opt-in.",
                "Send Cross-Origin-Embedder-Policy: require-corp (or credentialless) if the app "
                "needs SharedArrayBuffer / cross-origin isolation.",
                "CWE-200",
            ),
            (
                "cross-origin-opener-policy",
                Category.MISCONFIG,
                Severity.INFO,
                "Missing Cross-Origin-Opener-Policy",
                "Without COOP, a malicious site can open the page in a popup and reach into its "
                "window object across origins.",
                "Send Cross-Origin-Opener-Policy: same-origin.",
                "CWE-200",
            ),
            (
                "cross-origin-resource-policy",
                Category.MISCONFIG,
                Severity.INFO,
                "Missing Cross-Origin-Resource-Policy",
                "Without CORP, the resource can be loaded by any origin (subject to CORS); useful "
                "as defence-in-depth against Spectre-style attacks.",
                "Send Cross-Origin-Resource-Policy: same-origin.",
                "CWE-200",
            ),
            (
                "x-dns-prefetch-control",
                Category.MISCONFIG,
                Severity.INFO,
                "Missing X-DNS-Prefetch-Control",
                "Without X-DNS-Prefetch-Control: off, browsers may prefetch cross-origin hostnames "
                "in links, leaking user behaviour to third-party DNS resolvers.",
                "Send X-DNS-Prefetch-Control: off (or use <link rel=dns-prefetch> selectively).",
                "CWE-200",
            ),
            (
                "x-permitted-cross-domain-policies",
                Category.MISCONFIG,
                Severity.INFO,
                "Missing X-Permitted-Cross-Domain-Policies",
                "Without X-Permitted-Cross-Domain-Policies: none, legacy Flash / PDF plugins may "
                "embed the site cross-domain.",
                "Send X-Permitted-Cross-Domain-Policies: none.",
                "CWE-16",
            ),
            (
                "cache-control",
                Category.MISCONFIG,
                Severity.LOW,
                "Missing Cache-Control",
                "No Cache-Control header; sensitive responses may be cached by shared proxies or "
                "the browser, enabling access after logout / on shared devices.",
                "Send Cache-Control: no-store (or no-cache, must-revalidate) for authenticated "
                "and sensitive responses.",
                "CWE-525",
            ),
            (
                "pragma",
                Category.MISCONFIG,
                Severity.INFO,
                "Missing Pragma: no-cache (legacy)",
                "No Pragma header; legacy HTTP/1.0 caches may still store the response. Modern "
                "Cache-Control is preferred, but Pragma adds belt-and-braces protection.",
                "Send Pragma: no-cache on sensitive responses alongside Cache-Control.",
                "CWE-525",
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
