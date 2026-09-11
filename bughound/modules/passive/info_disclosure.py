"""Information disclosure: exposed files, banners, directory listing, errors."""

from __future__ import annotations

import re
from urllib.parse import urljoin

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register

SENSITIVE_PATHS: list[tuple[str, str, Severity, str]] = [
    (".git/config", "[core]", Severity.HIGH, "Exposed .git repository"),
    (".git/HEAD", "ref:", Severity.HIGH, "Exposed .git repository"),
    (".env", "=", Severity.HIGH, "Exposed .env file"),
    (".svn/entries", "", Severity.MEDIUM, "Exposed .svn directory"),
    ("config.php.bak", "<?php", Severity.HIGH, "Exposed PHP backup file"),
    ("wp-config.php.bak", "<?php", Severity.HIGH, "Exposed WordPress config backup"),
    ("phpinfo.php", "phpinfo()", Severity.MEDIUM, "Exposed phpinfo()"),
    ("server-status", "Apache Server Status", Severity.MEDIUM, "Exposed Apache server-status"),
    (".DS_Store", "", Severity.LOW, "Exposed .DS_Store"),
    ("backup.zip", "", Severity.MEDIUM, "Exposed backup archive"),
    ("docker-compose.yml", "services:", Severity.MEDIUM, "Exposed docker-compose.yml"),
]

STACKTRACE_SIGNS = [
    "Traceback (most recent call last)",
    "java.lang.",
    "org.springframework",
    "System.Web.HttpException",
    "Warning: mysql_",
    "Fatal error:",
    "Microsoft OLE DB Provider",
]


@register
class InfoDisclosureModule(Module):
    name = "info-disclosure"
    categories = [Category.INFO_DISCLOSURE, Category.MISCONFIG]
    passive = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        # Server / technology banners
        headers = ctx.seed_headers
        for hname in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
            if hname in headers:
                findings.append(
                    Finding(
                        category=Category.INFO_DISCLOSURE,
                        title=f"Technology disclosed via '{hname}' header",
                        severity=Severity.INFO,
                        confidence="firm",
                        url=ctx.base_url,
                        description=f"The '{hname}' header reveals server/framework details useful to an attacker.",
                        evidence=f"{hname}: {headers[hname]}",
                        remediation=f"Remove or obfuscate the '{hname}' response header.",
                        cwe="CWE-200",
                        module=self.name,
                        verified=True,
                    )
                )

        # Stack traces / verbose errors on the landing page
        for sign in STACKTRACE_SIGNS:
            if sign in ctx.seed_html:
                findings.append(
                    Finding(
                        category=Category.INFO_DISCLOSURE,
                        title="Verbose error / stack trace disclosed",
                        severity=Severity.MEDIUM,
                        confidence="firm",
                        url=ctx.base_url,
                        description="The response contains a stack trace or verbose error message.",
                        evidence=f"Matched signature: {sign!r}",
                        remediation="Disable debug mode in production; return generic error pages.",
                        cwe="CWE-209",
                        module=self.name,
                        verified=True,
                    )
                )
                break

        # Well-known sensitive files
        for path, needle, sev, title in SENSITIVE_PATHS:
            url = urljoin(ctx.base_url.rstrip("/") + "/", path)
            resp = await ctx.client.get(url, follow_redirects=False)
            if not resp.ok or resp.status != 200:
                continue
            body = resp.text
            if needle and needle not in body:
                continue
            if not body.strip():
                continue
            findings.append(
                Finding(
                    category=Category.INFO_DISCLOSURE,
                    title=title,
                    severity=sev,
                    confidence="confirmed" if needle else "firm",
                    url=resp.url,
                    description=f"A sensitive resource is publicly accessible at {path}.",
                    evidence=f"GET {url} -> 200; body starts: {body[:120]!r}",
                    remediation="Block access to VCS/backup/config files at the web server and remove them from webroot.",
                    cwe="CWE-538",
                    module=self.name,
                    verified=True,
                )
            )

        # Directory listing
        if re.search(r"<title>Index of /", ctx.seed_html) or "Directory listing for" in ctx.seed_html:
            findings.append(
                Finding(
                    category=Category.MISCONFIG,
                    title="Directory listing enabled",
                    severity=Severity.LOW,
                    confidence="firm",
                    url=ctx.base_url,
                    description="Autoindex/directory listing is enabled, exposing file names.",
                    evidence="Response body contains a directory index.",
                    remediation="Disable automatic directory indexing.",
                    cwe="CWE-548",
                    module=self.name,
                    verified=True,
                )
            )
        return findings
