"""Heuristic/advisory checks for classes that need context or manual follow-up.

These produce honestly-labeled observations (CSRF-less forms, IDOR-candidate
parameters, XML endpoints, login flows) rather than confirmed exploits, since
IDOR, privilege escalation, deserialization, race conditions, OAuth/SAML and
MFA bypasses generally require authenticated context and human judgement.
"""

from __future__ import annotations

import re

from bs4 import BeautifulSoup

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register

ID_PARAM_RE = re.compile(r"^(id|uid|user_?id|account|order|invoice|doc|file|num|pid|gid)$", re.I)


@register
class AdvisoryModule(Module):
    name = "advisory"
    categories = [
        Category.CSRF,
        Category.IDOR,
        Category.PRIV_ESC,
        Category.DESERIALIZATION,
        Category.RACE_CONDITION,
        Category.OAUTH_SAML,
        Category.SESSION,
        Category.BRUTE_FORCE,
        Category.MFA_BYPASS,
        Category.XXE,
    ]
    passive = False
    aggressive_required = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        soup = BeautifulSoup(ctx.seed_html, "html.parser")

        # CSRF: state-changing forms without an anti-CSRF token field.
        for form in soup.find_all("form"):
            method = (form.get("method") or "get").lower()
            if method != "post":
                continue
            inputs = form.find_all("input")
            has_token = any(
                re.search(r"csrf|token|authenticity|nonce", (i.get("name") or ""), re.I)
                for i in inputs
            )
            if not has_token:
                findings.append(
                    Finding(
                        category=Category.CSRF,
                        title="POST form without anti-CSRF token",
                        severity=Severity.MEDIUM,
                        confidence="tentative",
                        url=ctx.base_url,
                        description="A state-changing form has no visible CSRF token; verify CSRF protection.",
                        evidence=f"<form action={form.get('action')!r} method=post> has no token field.",
                        remediation="Add per-session/per-request CSRF tokens or use SameSite cookies + origin checks.",
                        cwe="CWE-352",
                        module=self.name,
                        verified=False,
                    )
                )

        # Login form => auth-related classes need manual testing.
        pw = soup.find("input", {"type": "password"})
        if pw:
            findings.append(
                Finding(
                    category=Category.BRUTE_FORCE,
                    title="Authentication form detected (manual auth testing recommended)",
                    severity=Severity.INFO,
                    confidence="tentative",
                    url=ctx.base_url,
                    description=(
                        "A login form was found. Manually test rate limiting/lockout (brute-force, "
                        "credential stuffing), MFA bypass, session fixation, and OAuth/SAML config."
                    ),
                    evidence="Password input present on page.",
                    remediation="Enforce rate limiting/lockout, MFA, session rotation on login, and validate SSO config.",
                    cwe="CWE-307",
                    module=self.name,
                    verified=False,
                )
            )

        # IDOR-candidate parameters.
        for rt in ctx.request_targets:
            for param in rt.params:
                if ID_PARAM_RE.match(param) and rt.params[param].isdigit():
                    findings.append(
                        Finding(
                            category=Category.IDOR,
                            title=f"IDOR-candidate parameter '{param}'",
                            severity=Severity.INFO,
                            confidence="tentative",
                            url=rt.url,
                            description=(
                                f"'{param}' looks like a direct object reference. Manually test access "
                                "control by changing it across accounts (IDOR / horizontal & vertical priv-esc)."
                            ),
                            evidence=f"{param}={rt.params[param]} (numeric object identifier).",
                            remediation="Enforce per-object authorization server-side; use unguessable references.",
                            cwe="CWE-639",
                            module=self.name,
                            verified=False,
                        )
                    )
                    break
        return findings
