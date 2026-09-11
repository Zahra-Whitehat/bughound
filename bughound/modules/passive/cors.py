"""CORS misconfiguration checks."""

from __future__ import annotations

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register

EVIL_ORIGIN = "https://bughound-evil.example"


@register
class CorsModule(Module):
    name = "cors"
    categories = [Category.CORS]
    passive = True  # only sends a benign Origin header, no payloads

    async def run(self, ctx: ScanContext) -> list[Finding]:
        resp = await ctx.client.get(ctx.base_url, headers={"Origin": EVIL_ORIGIN})
        if not resp.ok:
            return []
        acao = resp.headers.get("access-control-allow-origin")
        acac = resp.headers.get("access-control-allow-credentials", "").lower()
        if not acao:
            return []

        findings: list[Finding] = []
        if acao == EVIL_ORIGIN:
            sev = Severity.HIGH if acac == "true" else Severity.MEDIUM
            findings.append(
                Finding(
                    category=Category.CORS,
                    title="CORS reflects arbitrary Origin",
                    severity=sev,
                    confidence="confirmed",
                    url=resp.url,
                    description=(
                        "The server reflects an attacker-supplied Origin in "
                        "Access-Control-Allow-Origin"
                        + (" with credentials allowed" if acac == "true" else "")
                        + ", letting a malicious site read authenticated responses."
                    ),
                    evidence=f"Sent Origin: {EVIL_ORIGIN} -> ACAO: {acao}, ACAC: {acac or 'unset'}",
                    request=f"GET {ctx.base_url}\nOrigin: {EVIL_ORIGIN}",
                    remediation="Validate Origin against an allowlist; never reflect arbitrary origins with credentials.",
                    cwe="CWE-942",
                    module=self.name,
                    verified=True,
                )
            )
        elif acao == "*" and acac == "true":
            findings.append(
                Finding(
                    category=Category.CORS,
                    title="CORS wildcard with credentials",
                    severity=Severity.MEDIUM,
                    confidence="firm",
                    url=resp.url,
                    description="Access-Control-Allow-Origin: * combined with credentials is invalid and risky.",
                    evidence=f"ACAO: * ; ACAC: {acac}",
                    remediation="Do not combine a wildcard origin with Access-Control-Allow-Credentials.",
                    cwe="CWE-942",
                    module=self.name,
                    verified=True,
                )
            )
        return findings
