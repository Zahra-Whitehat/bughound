"""NoSQL injection detection (operator injection / differential / auth bypass)."""

from __future__ import annotations

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register
from ._util import baseline, send_with_param

ERROR_SIGNS = ["MongoError", "unexpected token", "$where", "CastError", "BSONError", "MongoServerError"]

# Authentication-success markers: if they appear ONLY after operator
# injection, the query logic was rewritten -> real, exploitable auth bypass.
AUTH_SUCCESS_MARKERS = [
    "welcome back", "welcome,", "dashboard", "logged in", "log out",
    "logout", "sign out", "my account", "admin panel",
]


@register
class NoSqliModule(Module):
    name = "nosqli"
    categories = [Category.NOSQLI]
    passive = False
    aggressive_required = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rt in ctx.request_targets:
            base = await baseline(ctx.client, rt)
            base_marks = self._auth_markers(base.text) if base.ok else set()
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

                # Strongest signal first: did the operator injection log us in
                # without credentials? New auth markers = proven auth bypass.
                new_marks = [m for m in self._auth_markers(r.text) if m not in base_marks]
                if new_marks:
                    findings.append(
                        Finding(
                            category=Category.NOSQLI,
                            title=f"NoSQL operator injection -> authentication bypass via '{param}'",
                            severity=Severity.CRITICAL,
                            confidence="confirmed",
                            url=rt.url,
                            description=(
                                f"Injecting the [$ne] operator into '{param}' rewrote the query logic "
                                "(user != anything) and returned an authenticated page without valid "
                                "credentials."
                            ),
                            evidence=(
                                f"Sent {param}[$ne]=bughound; response gained authentication markers "
                                f"absent from the baseline: {', '.join(new_marks[:5])}"
                            ),
                            request=f"{rt.method} {rt.url} ({param}[$ne]=bughound)",
                            response_excerpt=r.text[:300],
                            remediation=(
                                "Cast/validate input types server-side; reject object operators from "
                                "query/body params; never mix user input into query selectors."
                            ),
                            cwe="CWE-943",
                            module=self.name,
                            verified=True,
                        )
                    )
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

    @staticmethod
    def _auth_markers(text: str) -> set[str]:
        low = (text or "").lower()
        return {m for m in AUTH_SUCCESS_MARKERS if m in low}
