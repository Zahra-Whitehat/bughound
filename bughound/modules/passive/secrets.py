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
    # Cloud / IaaS
    ("AWS access key", r"AKIA[0-9A-Z]{16}"),
    ("AWS secret key", r"(?i)aws[_\-]?secret[_\-]?(access)?[_\-]?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]"),
    ("Google API key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("Google OAuth access token", r"ya29\.[0-9A-Za-z\-_]+"),
    ("GCP service account private key", r"\"type\":\s*\"service_account\""),
    ("Azure storage account key", r"(?i)accountkey=[A-Za-z0-9+/=]{86,}"),
    ("Azure connection string", r"(?i)defaultendpointsprotocol=https?;accountname=[^;\"']+;accountkey=[A-Za-z0-9+/=]{86,}"),
    # SaaS
    ("Slack token", r"xox[baprs]-[0-9A-Za-z\-]{10,48}"),
    ("Slack webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    ("Stripe secret key", r"sk_live_[0-9A-Za-z]{24,}"),
    ("Stripe restricted key", r"rk_live_[0-9A-Za-z]{24,}"),
    ("Stripe publishable key", r"pk_live_[0-9A-Za-z]{24,}"),
    ("GitHub token", r"gh[pousr]_[0-9A-Za-z]{36,}"),
    ("GitHub OAuth token", r"gho_[0-9A-Za-z]{36,}"),
    ("GitHub app token", r"(?:ghu|ghs)_[0-9A-Za-z]{36,}"),
    ("GitLab token", r"glpat-[0-9A-Za-z\-_]{20}"),
    ("GitHub refresh token", r"ghr_[0-9A-Za-z]{76}"),
    ("Twilio API key", r"SK[0-9a-fA-F]{32}"),
    ("Twilio account SID", r"AC[a-f0-9]{32}"),
    ("SendGrid API key", r"SG\.[A-Za-z0-9_\-]{16,32}\.[A-Za-z0-9_\-]{32,64}"),
    ("Mailgun API key", r"key-[0-9a-zA-Z]{32}"),
    ("Mailgun pub key", r"pubkey-[0-9a-zA-Z]{32}"),
    ("Mandrill API key (in assignment)", r"(?i)mandrill[_\-]?(api[_\-]?)?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9]{32}-[A-Za-z0-9]{8}['\"]"),
    ("Postmark API token (in assignment)", r"(?i)postmark[_\-]?(api[_\-]?)?(server[_\-]?)?token['\"]?\s*[:=]\s*['\"][a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}['\"]"),
    ("Square access token", r"sq0atp-[0-9A-Za-z\-_]{22}"),
    ("Square OAuth secret", r"sq0csp-[0-9A-Za-z\-_]{43}"),
    ("PayPal braintree access token", r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
    ("Twitch client secret (in assignment)", r"(?i)twitch[_\-]?(client[_\-]?)?secret['\"]?\s*[:=]\s*['\"][a-z0-9]{30}['\"]"),
    ("Twitter / X bearer token (in assignment)", r"(?i)bearer['\"]?\s*[:=]\s*['\"]A[A-Za-z0-9%-_]{40,}['\"]"),
    ("Twitter / X access token", r"(?i)twitter[_\-]?api[_\-]?(secret|key)['\"]?\s*[:=]\s*['\"][A-Za-z0-9]{35,}['\"]"),
    ("Discord bot token", r"[MN][A-Za-z0-9]{23}\.[\w-]{6}\.[\w-]{27}"),
    ("Linear API key", r"lin_api_[A-Za-z0-9]{40}"),
    ("Notion integration token", r"secret_[A-Za-z0-9]{43}"),
    ("Asana PAT", r"(?i)1\/[0-9]+:[A-Za-z0-9]+"),
    ("Jira / Atlassian API token", r"(?i)ATATT3[A-Za-z0-9_\-=]{180,}"),
    ("Asana client ID", r"(?i)asana[_\-]?key['\"]?\s*[:=]\s*['\"][^'\"]+['\"]"),
    # Database URLs (very common leak)
    ("Database URL", r"(?i)(postgres|postgresql|mysql|mongodb(\+srv)?|redis|amqp|mssql)://[^:@\s\"']+:[^@\s\"']+@[^\"'\s]+"),
    ("JDBC connection", r"jdbc:[a-z]+://[^:@\s\"']+:[^@\s\"']+@[^\"'\s]+"),
    ("Generic connection string with creds", r"(?i)(server|host|data source)\s*=\s*[^;]+;[^;]*password\s*=\s*[^;]+"),
    # Private keys
    ("Private key block", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ("PGP private key block", r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
    # Generic secrets / tokens
    ("Generic API key assignment", r"(?i)(api[_-]?key|secret|passwd|password|token|access[_-]?token|client[_-]?secret|auth[_-]?token)['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
    ("Generic Bearer token", r"(?i)bearer\s+[A-Za-z0-9\-\._~+\/]{32,}"),
    ("Generic JWT in assignment", r"(?i)(token|jwt)['\"]?\s*[:=]\s*['\"]eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*['\"]"),
    # Misc
    ("Twitch webhook secret", r"(?i)twitch[_\-]?secret['\"]?\s*[:=]\s*['\"][A-Za-z0-9]{30}['\"]"),
    ("Heroku API key", r"(?i)heroku[_\-]?api[_\-]?key['\"]?\s*[:=]\s*['\"][0-9a-f]{32}['\"]"),
    ("Vault token", r"hvs\.[A-Za-z0-9_-]{90,}"),
    ("Shopify access token", r"shpat_[a-fA-F0-9]{32}"),
    ("Shopify custom app token", r"shpca_[a-fA-F0-9]{32}"),
    ("Shopify partner API token", r"shppa_[a-fA-F0-9]{32}"),
    ("Slack config webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{16,}"),
    ("Sentry DSN", r"https?://[a-f0-9]{32}@(?:o\d+\.ingest\.)?sentry\.io/\d+"),
    ("Buildkite token", r"bkua_[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
    ("NPM token", r"npm_[A-Za-z0-9]{36}"),
    ("Pypi upload token", r"pypi-AgEIcHlpaVJlc2V0[A-Za-z0-9-_]+"),
    ("Contentful delivery token", r"(?i)contentful[_\-]?delivery[_\-]?token['\"]?\s*[:=]\s*['\"][A-Za-z0-9_-]{43}['\"]"),
    ("Algolia API key (in assignment)", r"(?i)algolia[_\-]?(api[_\-]?key|admin[_\-]?key)['\"]?\s*[:=]\s*['\"][A-Fa-f0-9]{32}['\"]"),
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
