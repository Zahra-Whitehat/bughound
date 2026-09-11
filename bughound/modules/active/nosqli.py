"""NoSQL injection detection (operator injection / differential)."""

from __future__ import annotations

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register
from ._util import baseline, send_with_param

ERROR_SIGNS = ["MongoError", "unexpected token", "$where", "CastError", "BSONError", "MongoServerError"]


@register
class NoSqliModule(Module):
    name = "nosqli"
    categories = [Category.NOSQLI]
    passive = False
    aggressive_required = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rt in ctx.request_targets:
            for param in rt.params:
                # Operator injection using param[$ne] style keys
                params = dict(rt.params)
                del params[param]
                params[f"{param}[$ne]"] = "bughound"
                if rt.method.upper() == "POST":
                    r = await ctx.client.post(rt.url, data=params)
                else:
                    r = await ctx.client.get(rt.url, params=params)
                if not r.ok:
                    continue
                if any(s in r.text for s in ERROR_SIGNS):
                    findings.append(
                        Finding(
                            category=Category.NOSQLI,
                            title=f"NoSQL error triggered via '{param}'",
                            severity=Severity.HIGH,
                            confidence="firm",
                            url=rt.url,
                            description=f"A NoSQL operator payload in '{param}' produced a database error.",
                            evidence=f"Sent {param}[$ne]=... ; NoSQL error signature in response.",
                            request=f"{rt.method} {rt.url} ({param}[$ne]=bughound)",
                            response_excerpt=r.text[:300],
                            remediation="Cast/validate input types; reject object operators from query/body params.",
                            cwe="CWE-943",
                            module=self.name,
                            verified=False,
                        )
                    )
                    continue

                # Differential: [$ne] should behave differently from a literal.
                base = await baseline(ctx.client, rt)
                inj = await send_with_param(ctx.client, rt, param, rt.params[param] + "' || '1'=='1")
                if base.ok and inj.ok and abs(len(inj.text) - len(base.text)) > 100:
                    findings.append(
                        Finding(
                            category=Category.NOSQLI,
                            title=f"Possible NoSQL injection in '{param}'",
                            severity=Severity.MEDIUM,
                            confidence="tentative",
                            url=rt.url,
                            description=f"Response length changed markedly for a NoSQL-style payload in '{param}'.",
                            evidence=f"len(base)={len(base.text)} len(injected)={len(inj.text)}",
                            request=f"{rt.method} {rt.url} ({param}=...' || '1'=='1)",
                            remediation="Validate input types and avoid interpolating input into queries.",
                            cwe="CWE-943",
                            module=self.name,
                            verified=False,
                        )
                    )
        return findings
