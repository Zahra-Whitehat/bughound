"""Information disclosure: exposed files, banners, directory listing, errors."""

from __future__ import annotations

import re
from urllib.parse import urljoin

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register

SENSITIVE_PATHS: list[tuple[str, str, Severity, str]] = [
    (".git/config", "[core]", Severity.HIGH, "Exposed .git repository"),
    (".git/HEAD", "ref:", Severity.HIGH, "Exposed .git repository"),
    (".git/index", "", Severity.HIGH, "Exposed .git index (file listing)"),
    (".git/logs/HEAD", "", Severity.HIGH, "Exposed .git reflog"),
    (".env", "=", Severity.HIGH, "Exposed .env file"),
    (".env.local", "=", Severity.HIGH, "Exposed .env.local"),
    (".env.production", "=", Severity.HIGH, "Exposed .env.production"),
    (".env.staging", "=", Severity.HIGH, "Exposed .env.staging"),
    (".svn/entries", "", Severity.MEDIUM, "Exposed .svn directory"),
    (".svn/wc.db", "", Severity.MEDIUM, "Exposed .svn wc.db"),
    (".hg/store", "", Severity.MEDIUM, "Exposed Mercurial repository"),
    (".bzr/README", "", Severity.MEDIUM, "Exposed Bazaar repository"),
    ("config.php.bak", "<?php", Severity.HIGH, "Exposed PHP backup file"),
    ("wp-config.php.bak", "<?php", Severity.HIGH, "Exposed WordPress config backup"),
    ("wp-config.php", "DB_PASSWORD", Severity.HIGH, "Exposed WordPress config"),
    ("phpinfo.php", "phpinfo()", Severity.MEDIUM, "Exposed phpinfo()"),
    ("info.php", "phpinfo()", Severity.MEDIUM, "Exposed phpinfo() (info.php)"),
    ("test.php", "phpinfo()", Severity.MEDIUM, "Exposed test.php with phpinfo()"),
    ("server-status", "Apache Server Status", Severity.MEDIUM, "Exposed Apache server-status"),
    ("server-info", "Apache Server Information", Severity.MEDIUM, "Exposed Apache server-info"),
    (".DS_Store", "", Severity.LOW, "Exposed .DS_Store"),
    (".htaccess", "", Severity.MEDIUM, "Exposed .htaccess"),
    (".htpasswd", ":", Severity.HIGH, "Exposed .htpasswd (credential file)"),
    ("backup.zip", "", Severity.MEDIUM, "Exposed backup archive"),
    ("backup.tar.gz", "", Severity.MEDIUM, "Exposed backup tarball"),
    ("backup.sql", "CREATE TABLE", Severity.HIGH, "Exposed SQL backup"),
    ("db.sql", "CREATE TABLE", Severity.HIGH, "Exposed SQL dump (db.sql)"),
    ("dump.sql", "CREATE TABLE", Severity.HIGH, "Exposed SQL dump (dump.sql)"),
    ("docker-compose.yml", "services:", Severity.MEDIUM, "Exposed docker-compose.yml"),
    ("docker-compose.yaml", "services:", Severity.MEDIUM, "Exposed docker-compose.yaml"),
    ("Dockerfile", "FROM", Severity.LOW, "Exposed Dockerfile"),
    ("Procfile", ":", Severity.LOW, "Exposed Procfile"),
    ("package.json", "\"name\"", Severity.LOW, "Exposed package.json"),
    ("package-lock.json", "\"lockfileVersion\"", Severity.LOW, "Exposed package-lock.json"),
    ("composer.json", "\"require\"", Severity.LOW, "Exposed composer.json"),
    ("composer.lock", "\"content-hash\"", Severity.LOW, "Exposed composer.lock"),
    ("Gemfile.lock", "GEM", Severity.LOW, "Exposed Gemfile.lock"),
    ("requirements.txt", "==", Severity.LOW, "Exposed requirements.txt"),
    ("Pipfile.lock", "\"version\"", Severity.LOW, "Exposed Pipfile.lock"),
    ("yarn.lock", "__metadata", Severity.LOW, "Exposed yarn.lock"),
    ("id_rsa", "PRIVATE KEY", Severity.CRITICAL, "Exposed SSH private key (id_rsa)"),
    ("id_dsa", "PRIVATE KEY", Severity.CRITICAL, "Exposed SSH private key (id_dsa)"),
    ("id_ecdsa", "PRIVATE KEY", Severity.CRITICAL, "Exposed SSH private key (id_ecdsa)"),
    ("id_ed25519", "PRIVATE KEY", Severity.CRITICAL, "Exposed SSH private key (id_ed25519)"),
    (".ssh/id_rsa", "PRIVATE KEY", Severity.CRITICAL, "Exposed SSH private key"),
    ("credentials.json", "private_key", Severity.CRITICAL, "Exposed GCP service-account credentials"),
    ("service-account.json", "private_key", Severity.CRITICAL, "Exposed GCP service account"),
    ("firebase-adminsdk", "private_key", Severity.CRITICAL, "Exposed Firebase admin key"),
    (".aws/credentials", "aws_access_key_id", Severity.CRITICAL, "Exposed AWS credentials file"),
    (".bash_history", "", Severity.MEDIUM, "Exposed shell history"),
    (".bashrc", "", Severity.LOW, "Exposed shell config (.bashrc)"),
    (".zshrc", "", Severity.LOW, "Exposed shell config (.zshrc)"),
    (".viminfo", "", Severity.LOW, "Exposed vim info"),
    (".mysql_history", "", Severity.MEDIUM, "Exposed MySQL history"),
    (".psql_history", "", Severity.MEDIUM, "Exposed psql history"),
    ("web.config", "configuration", Severity.MEDIUM, "Exposed IIS web.config"),
    ("Web.config", "configuration", Severity.MEDIUM, "Exposed IIS Web.config"),
    ("app.config", "configuration", Severity.MEDIUM, "Exposed .NET app.config"),
    ("settings.py", "SECRET_KEY", Severity.HIGH, "Exposed Django settings.py"),
    ("local_settings.py", "SECRET_KEY", Severity.HIGH, "Exposed Django local_settings.py"),
    ("settings.json", "\"connectionString\"", Severity.HIGH, "Exposed settings.json"),
    ("appsettings.json", "\"connectionStrings\"", Severity.HIGH, "Exposed appsettings.json"),
    ("appsettings.Development.json", "\"connectionStrings\"", Severity.HIGH, "Exposed dev appsettings"),
    ("application.properties", "spring", Severity.HIGH, "Exposed Spring properties"),
    ("application.yml", "spring:", Severity.HIGH, "Exposed Spring YAML config"),
    ("config/database.yml", "adapter", Severity.HIGH, "Exposed Rails database.yml"),
    ("config/secrets.yml", "production", Severity.HIGH, "Exposed Rails secrets.yml"),
    ("config/master.key", "", Severity.CRITICAL, "Exposed Rails master.key"),
    ("config/credentials.yml.enc", "", Severity.HIGH, "Exposed Rails encrypted credentials"),
    ("coverage/index.html", "coverage", Severity.LOW, "Exposed code-coverage report"),
    ("coverage/lcov.info", "TN:", Severity.LOW, "Exposed LCOV coverage report"),
    ("coverage/", "coverage", Severity.LOW, "Exposed coverage directory"),
    (".nyc_output", "", Severity.LOW, "Exposed nyc coverage output"),
    ("npm-debug.log", "npm", Severity.LOW, "Exposed npm-debug.log"),
    ("yarn-error.log", "error", Severity.LOW, "Exposed yarn-error.log"),
    ("php_error.log", "PHP", Severity.LOW, "Exposed PHP error log"),
    ("error_log", "error", Severity.LOW, "Exposed error_log"),
    ("debug.log", "debug", Severity.LOW, "Exposed debug.log"),
    ("access.log", "GET", Severity.LOW, "Exposed access.log"),
    (".well-known/security.txt", "Contact", Severity.INFO, "security.txt (informational)"),
    ("composer.phar", "", Severity.LOW, "Exposed composer.phar binary"),
    ("admin.php", "login", Severity.MEDIUM, "Exposed admin.php"),
    ("phpmyadmin/", "phpMyAdmin", Severity.HIGH, "Exposed phpMyAdmin"),
    ("phpMyAdmin/", "phpMyAdmin", Severity.HIGH, "Exposed phpMyAdmin (Camel)"),
    ("pma/", "phpMyAdmin", Severity.HIGH, "Exposed phpMyAdmin (pma alias)"),
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
