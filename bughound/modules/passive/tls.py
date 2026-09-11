"""TLS / transport-security checks."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register


@register
class TlsModule(Module):
    name = "tls"
    categories = [Category.TLS]
    passive = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        parsed = urlparse(ctx.base_url)
        host = parsed.hostname or ctx.target.host
        findings: list[Finding] = []

        if parsed.scheme == "http":
            # Does it redirect to HTTPS?
            resp = await ctx.client.get(f"http://{host}/", follow_redirects=False)
            location = resp.headers.get("location", "") if resp.ok else ""
            if not location.startswith("https://"):
                findings.append(
                    Finding(
                        category=Category.TLS,
                        title="HTTP not redirected to HTTPS",
                        severity=Severity.MEDIUM,
                        confidence="firm",
                        url=f"http://{host}/",
                        description="Plain HTTP is served without redirecting to HTTPS; traffic can be intercepted.",
                        evidence=f"GET http://{host}/ -> {resp.status}, Location: {location or 'none'}",
                        remediation="Redirect all HTTP to HTTPS and enable HSTS.",
                        cwe="CWE-319",
                        module=self.name,
                        verified=True,
                    )
                )

        port = parsed.port or (443 if parsed.scheme != "http" else 443)
        try:
            cert = self._fetch_cert(host, port)
        except Exception as exc:  # noqa: BLE001
            ctx.log(f"tls: could not fetch cert for {host}:{port}: {exc}")
            return findings

        not_after = cert.get("notAfter")
        if not_after:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            days = (expires - datetime.now(timezone.utc)).days
            if days < 0:
                findings.append(
                    Finding(
                        category=Category.TLS,
                        title="Expired TLS certificate",
                        severity=Severity.HIGH,
                        confidence="confirmed",
                        url=ctx.base_url,
                        description=f"The TLS certificate expired {abs(days)} days ago.",
                        evidence=f"notAfter={not_after}",
                        remediation="Renew the certificate and automate renewal (e.g. ACME).",
                        cwe="CWE-324",
                        module=self.name,
                        verified=True,
                    )
                )
            elif days < 15:
                findings.append(
                    Finding(
                        category=Category.TLS,
                        title="TLS certificate expiring soon",
                        severity=Severity.LOW,
                        confidence="firm",
                        url=ctx.base_url,
                        description=f"The TLS certificate expires in {days} days.",
                        evidence=f"notAfter={not_after}",
                        remediation="Renew the certificate and automate renewal.",
                        module=self.name,
                        verified=True,
                    )
                )
        return findings

    @staticmethod
    def _fetch_cert(host: str, port: int) -> dict:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.getpeercert() or {}
