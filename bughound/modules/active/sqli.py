"""SQL injection detection (error-based, boolean-based, and time-based blind)."""

from __future__ import annotations

import asyncio
import re
from difflib import SequenceMatcher

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
    r"sqlite3\.OperationalError",
    r"sqlalchemy\.exc\.\w*Error",
    r"org\.postgresql\.util\.PSQLException",
    r"com\.mysql\.jdbc\.exceptions",
    r"Data source rejected establishment of connection",
    r"supplied argument is not a valid \w+ result",
]
SQL_ERROR_RE = re.compile("|".join(SQL_ERRORS), re.IGNORECASE)

# (dialect label, payload suffix, expected extra delay in seconds)
TIME_PAYLOADS = [
    ("MySQL/MariaDB", "' OR SLEEP({d})-- -", 1),
    ("PostgreSQL", "'; SELECT pg_sleep({d})-- -", 1),
    ("MSSQL", "'; WAITFOR DELAY '0:0:{d}'-- -", 1),
    ("Oracle", "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{d})-- -", 1),
    ("SQLite", "' OR (SELECT COUNT(*) FROM sqlite_master AS t1, sqlite_master AS t2, "
     "sqlite_master AS t3)>0-- -", 0),  # no native sleep; skipped for timing, kept for completeness
]

DELAY_SECONDS = 4
TIME_THRESHOLD = 2.5  # observed extra delay must clear this to count as a hit
CONTENT_SIMILARITY_THRESHOLD = 0.98  # true/false pages this similar are "the same page"


def _similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    return SequenceMatcher(None, a, b).ratio()


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
                found = await self._check_error_based(ctx, rt, param)
                if found:
                    findings.append(found)
                    continue

                found = await self._check_boolean_based(ctx, rt, param)
                if found:
                    findings.append(found)
                    continue

                found = await self._check_time_based(ctx, rt, param)
                if found:
                    findings.append(found)

        return findings

    async def _check_error_based(self, ctx: ScanContext, rt, param: str) -> Finding | None:
        r = await send_with_param(ctx.client, rt, param, rt.params[param] + "'\"")
        if not r.ok:
            return None
        m = SQL_ERROR_RE.search(r.text)
        if not m:
            return None
        return Finding(
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

    async def _check_boolean_based(self, ctx: ScanContext, rt, param: str) -> Finding | None:
        base = await baseline(ctx.client, rt)
        true_r = await send_with_param(ctx.client, rt, param, rt.params[param] + "' AND '1'='1")
        false_r = await send_with_param(ctx.client, rt, param, rt.params[param] + "' AND '1'='2")
        if not (base.ok and true_r.ok and false_r.ok):
            return None

        # A real boolean-blind vuln: the TRUE payload's page looks like baseline,
        # the FALSE payload's page looks different from both. Compare *content*,
        # not raw length, and also treat a status-code flip as a strong signal.
        status_signal = (
            true_r.status == base.status
            and false_r.status != base.status
        )

        true_vs_base = _similarity(true_r.text, base.text)
        false_vs_base = _similarity(false_r.text, base.text)
        true_vs_false = _similarity(true_r.text, false_r.text)

        content_signal = (
            true_vs_false < CONTENT_SIMILARITY_THRESHOLD
            and true_vs_base > false_vs_base
        )

        if not (status_signal or content_signal):
            return None

        return Finding(
            category=Category.SQLI,
            title=f"Possible boolean-based SQL injection in '{param}'",
            severity=Severity.HIGH,
            confidence="firm",
            url=rt.url,
            description=(
                f"Responses to '1'='1 vs '1'='2 payloads in '{param}' differ in content "
                "and/or status code, suggesting the input reaches a SQL boolean context."
            ),
            evidence=(
                f"status: base={base.status} true={true_r.status} false={false_r.status} | "
                f"similarity: true~base={true_vs_base:.3f} false~base={false_vs_base:.3f} "
                f"true~false={true_vs_false:.3f}"
            ),
            request=f"{rt.method} {rt.url} ({param}=...' AND '1'='1 / '1'='2)",
            remediation="Use parameterized queries; confirm manually with sqlmap.",
            cwe="CWE-89",
            module=self.name,
            verified=False,
        )

    async def _check_time_based(self, ctx: ScanContext, rt, param: str) -> Finding | None:
        # Establish a timing baseline first so slow/loaded targets don't false-positive.
        base = await baseline(ctx.client, rt)
        if not base.ok:
            return None

        for dialect, template, native_delay in TIME_PAYLOADS:
            if native_delay == 0:
                continue  # dialect has no clean timing primitive here; skip
            payload = template.format(d=DELAY_SECONDS)
            r = await send_with_param(ctx.client, rt, param, rt.params[param] + payload)
            if not r.ok:
                continue
            extra_delay = r.elapsed - base.elapsed
            if extra_delay < TIME_THRESHOLD:
                continue

            # Confirm with a second, differently-timed payload to rule out network jitter.
            confirm_delay_s = DELAY_SECONDS + 2
            confirm_payload = template.format(d=confirm_delay_s)
            r2 = await send_with_param(ctx.client, rt, param, rt.params[param] + confirm_payload)
            if not r2.ok:
                continue
            extra_delay_2 = r2.elapsed - base.elapsed
            # Elapsed time should scale roughly with the requested delay.
            if extra_delay_2 < confirm_delay_s - 1.5:
                continue

            return Finding(
                category=Category.SQLI,
                title=f"Time-based blind SQL injection in '{param}' ({dialect})",
                severity=Severity.CRITICAL,
                confidence="confirmed",
                url=rt.url,
                description=(
                    f"Injecting a {dialect} time-delay payload into '{param}' reliably "
                    "delayed the response by an amount matching the requested delay, "
                    "across two different delay values."
                ),
                evidence=(
                    f"baseline={base.elapsed:.2f}s | "
                    f"{DELAY_SECONDS}s payload -> +{extra_delay:.2f}s | "
                    f"{confirm_delay_s}s payload -> +{extra_delay_2:.2f}s"
                ),
                request=f"{rt.method} {rt.url} ({param}=<value>{payload})",
                remediation="Use parameterized queries / prepared statements; never build SQL from input.",
                cwe="CWE-89",
                module=self.name,
                verified=True,
            )
        return None
