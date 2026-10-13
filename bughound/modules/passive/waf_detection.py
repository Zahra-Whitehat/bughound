"""WAF / CDN / reverse-proxy detection.

Identifies the fronting security layer (Cloudflare, AWS WAF, Akamai, Sucuri,
Imperva, F5, Fortinet, etc.) from response headers and cookie names. This
shapes the rest of the engagement: a WAF changes which payloads are likely
to be blocked, and a CDN may cache responses independently of origin.

Strictly passive -- no payloads sent.
"""

from __future__ import annotations

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register
from ..recon_utils import WAF_SIGNATURES


@register
class WafDetectionModule(Module):
    name = "waf-detection"
    categories = [Category.RECON, Category.MISCONFIG]
    passive = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        resp = await ctx.client.get(ctx.base_url, follow_redirects=True)
        if not resp.ok:
            return []
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        detected: list[str] = []
        for header, needle, product in WAF_SIGNATURES:
            value = headers_lower.get(header, "")
            if not value:
                continue
            if not needle or needle.lower() in value.lower():
                if product not in detected:
                    detected.append(product)
        ctx.recon["waf"] = detected[0] if detected else None

        findings: list[Finding] = []
        if detected:
            findings.append(
                Finding(
                    category=Category.RECON,
                    title=f"WAF / CDN detected: {detected[0]}",
                    severity=Severity.INFO,
                    confidence="firm",
                    url=resp.url,
                    description=(
                        f"A fronting security layer ({detected[0]}) was identified from "
                        "response headers. Expect aggressive payloads to be filtered; "
                        "consider lower-and-slower active testing, and remember cached "
                        "responses may differ from origin."
                    ),
                    evidence="Detected: " + ", ".join(detected),
                    remediation="WAF presence is informational; tune payloads accordingly.",
                    references=["https://owasp.org/www-community/attacks/Web_Application_Firewall_bypass"],
                    module=self.name,
                    verified=True,
                )
            )
        else:
            findings.append(
                Finding(
                    category=Category.RECON,
                    title="No WAF / CDN detected via headers",
                    severity=Severity.INFO,
                    confidence="tentative",
                    url=resp.url,
                    description=(
                        "No WAF / CDN signatures were detected in the response headers. "
                        "The target may be directly exposed, or the WAF may be transparent "
                        "to headers -- behavioural probing during the active phase will "
                        "confirm."
                    ),
                    evidence=f"server={headers_lower.get('server', '?')}",
                    remediation="Confirm origin exposure; deploy a WAF if missing.",
                    module=self.name,
                    verified=False,
                )
            )
        return findings
