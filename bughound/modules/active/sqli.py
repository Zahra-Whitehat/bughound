"""SQL injection detection (error-based and boolean-based)."""

from __future__ import annotations

import re

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register
from ._util import baseline, send_with_param

SQL_ERRORS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"valid MySQL result",
    r"PostgreSQL.*ERROR",
    r"pg_query\(\)",
    r"SQLite/JDBCDriver",
    r"SQLite3::",
    r"System\.Data\.SQLite\.SQLiteException",
    r"Microsoft OLE DB Provider for SQL Server",
    r"Unclosed quotation mark after the character string",
    r"ORA-[0-9]{5}",
    r"Oracle error",
    r"quoted string not properly terminated",
]
SQL_ERROR_RE = re.compile("|".join(SQL_ERRORS), re.IGNORECASE)


@register
class SqliModule(Module):
    name = "sqli"
    categories = [Category.SQLI]
    passive = False
    aggressive_required = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rt in ctx.request_targets:
            for param in rt.params:
                # Error-based
                r = await send_with_param(ctx.client, rt, param, rt.params[param] + "'\"")
                if r.ok and SQL_ERROR_RE.search(r.text):
                    m = SQL_ERROR_RE.search(r.text)
                    findings.append(
                        Finding(
                            category=Category.SQLI,
                            title=f"Error-based SQL injection in '{param}'",
                            severity=Severity.CRITICAL,
                            confidence="confirmed",
                            url=rt.url,
                            description=f"Injecting a quote into '{param}' produced a database error.",
                            evidence=f"DB error signature: {m.group(0)!r}",
                            request=f"{rt.method} {rt.url} ({param}=<value>'\")",
                            response_excerpt=r.text[:300],
                            remediation="Use parameterized queries / prepared statements; never build SQL from input.",
                            cwe="CWE-89",
                            module=self.name,
                            verified=True,
                        )
                    )
                    continue

                # Boolean-based differential
                base = await baseline(ctx.client, rt)
                true_r = await send_with_param(
                    ctx.client, rt, param, rt.params[param] + "' AND '1'='1"
                )
                false_r = await send_with_param(
                    ctx.client, rt, param, rt.params[param] + "' AND '1'='2"
                )
                if base.ok and true_r.ok and false_r.ok:
                    if (
                        len(true_r.text) != len(false_r.text)
                        and abs(len(true_r.text) - len(base.text)) < abs(len(false_r.text) - len(base.text))
                        and len(true_r.text) > 0
                    ):
                        findings.append(
                            Finding(
                                category=Category.SQLI,
                                title=f"Possible boolean-based SQL injection in '{param}'",
                                severity=Severity.HIGH,
                                confidence="firm",
                                url=rt.url,
                                description=(
                                    f"Responses to '1'='1 vs '1'='2 payloads in '{param}' differ, "
                                    "suggesting the input reaches a SQL boolean context."
                                ),
                                evidence=(
                                    f"len(true)={len(true_r.text)} len(false)={len(false_r.text)} "
                                    f"len(base)={len(base.text)}"
                                ),
                                request=f"{rt.method} {rt.url} ({param}=...' AND '1'='1 / '1'='2)",
                                remediation="Use parameterized queries; validate confirming with sqlmap.",
                                cwe="CWE-89",
                                module=self.name,
                                verified=False,
                            )
                        )
        return findings
