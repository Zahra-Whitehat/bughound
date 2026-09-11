"""Hardcoded secrets, exposed JWTs and weak-crypto indicators."""

from __future__ import annotations

import base64
import json
import re
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register

SECRET_PATTERNS: list[tuple[str, str]] = [
    ("AWS access key", r"AKIA[0-9A-Z]{16}"),
    ("Google API key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("Slack token", r"xox[baprs]-[0-9A-Za-z\-]{10,48}"),
    ("Stripe secret key", r"sk_live_[0-9A-Za-z]{24,}"),
    ("GitHub token", r"gh[pousr]_[0-9A-Za-z]{36,}"),
    ("Private key block", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ("Generic API key assignment", r"(?i)(api[_-]?key|secret|passwd|password)['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
]

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")


def _b64json(part: str) -> dict | None:
    try:
        padded = part + "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:  # noqa: BLE001
        return None


@register
class SecretsModule(Module):
    name = "secrets"
    categories = [Category.CRYPTO, Category.INFO_DISCLOSURE]
    passive = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        corpus: list[tuple[str, str]] = [(ctx.base_url, ctx.seed_html)]

        # Pull a few linked JS files (same-origin only)
        soup = BeautifulSoup(ctx.seed_html, "html.parser")
        scripts = []
        for tag in soup.find_all("script", src=True):
            src = urljoin(ctx.base_url, tag["src"])
            if src.startswith(ctx.base_url.split("//", 1)[0]):
                scripts.append(src)
        for src in scripts[:8]:
            resp = await ctx.client.get(src)
            if resp.ok and resp.status == 200:
                corpus.append((src, resp.text))

        seen_secret: set[str] = set()
        for src_url, text in corpus:
            for label, pattern in SECRET_PATTERNS:
                for m in re.finditer(pattern, text):
                    snippet = m.group(0)[:80]
                    key = f"{label}:{snippet}"
                    if key in seen_secret:
                        continue
                    seen_secret.add(key)
                    findings.append(
                        Finding(
                            category=Category.CRYPTO,
                            title=f"Possible hardcoded secret: {label}",
                            severity=Severity.HIGH,
                            confidence="firm",
                            url=src_url,
                            description="A credential-like string was found in client-delivered content.",
                            evidence=f"{label} match: {snippet!r}",
                            remediation="Rotate the exposed secret and keep secrets server-side, never in client code.",
                            cwe="CWE-798",
                            module=self.name,
                            verified=True,
                        )
                    )
            for jwt in set(JWT_RE.findall(text)):
                header = _b64json(jwt.split(".")[0])
                alg = (header or {}).get("alg", "?")
                sev = Severity.HIGH if str(alg).lower() == "none" else Severity.MEDIUM
                findings.append(
                    Finding(
                        category=Category.CRYPTO,
                        title=f"JWT exposed in client content (alg={alg})",
                        severity=sev,
                        confidence="firm",
                        url=src_url,
                        description=(
                            "A JSON Web Token is present in client-delivered content."
                            + (" It uses alg=none, which disables signature verification." if str(alg).lower() == "none" else "")
                        ),
                        evidence=f"JWT header: {header}",
                        remediation="Do not ship JWTs in static content; reject alg=none and pin signing algorithms.",
                        cwe="CWE-347",
                        module=self.name,
                        verified=True,
                    )
                )
        return findings
