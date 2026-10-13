"""Backup / swap / versioned-file discovery.

For each URL discovered by the crawler, probes for common backup variants
(``.bak``, ``.old``, ``.orig``, ``~``, ``.swp``, ``.save``, ``.copy``,
``.tmp``, ``.zip``, ``.tar.gz``, ``.tgz``, ``.sql``, ``.rar``, ``.7z``) plus
editor artifacts (Vim ``.swp``, Emacs ``~``). Many deployments accidentally
leave these world-readable, leaking source code, configuration, and sometimes
secrets.

Passive: plain GETs only, no payloads. The probe list is small (~15 variants
per discovered path) so it stays under the same overall request budget as the
crawler.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register

# Backup suffixes appended to the full path.
BACKUP_SUFFIXES: list[str] = [
    ".bak", ".old", ".orig", ".save", ".copy", ".tmp", ".backup", ".bk",
    ".swp", ".swo", "~",
    ".zip", ".tar.gz", ".tgz", ".tar", ".sql", ".gz", ".rar", ".7z",
]

# Filename-only variants (prepend a leading dot, etc.).
PATH_LEAF_VARIANTS: list[str] = [
    # Vim swap file: .path.swp
    "",
]

# Specific high-value files that often get backed up centrally.
HIGH_VALUE_FILES: list[tuple[str, str]] = [
    # (path, label)
    ("/backup.zip", "backup archive at root"),
    ("/backup.tar.gz", "tar.gz backup at root"),
    ("/backup.sql", "SQL dump at root"),
    ("/db.sql", "SQL dump (db.sql)"),
    ("/database.sql", "SQL dump (database.sql)"),
    ("/dump.sql", "SQL dump (dump.sql)"),
    ("/site.zip", "site.zip archive at root"),
    ("/web.zip", "web.zip archive at root"),
    ("/www.zip", "www.zip archive at root"),
    ("/html.zip", "html.zip archive at root"),
    ("/archive.zip", "archive.zip at root"),
    ("/www.tar.gz", "www.tar.gz at root"),
    ("/config.php.bak", "PHP config backup"),
    ("/config.php~", "PHP config (Emacs backup)"),
    ("/wp-config.php.bak", "WordPress config backup"),
    ("/wp-config.php~", "WordPress config (Emacs backup)"),
    ("/.env.bak", "dotenv backup"),
    ("/.env~", "dotenv (Emacs backup)"),
    ("/settings.py.bak", "Django settings backup"),
    ("/database.yml.bak", "Rails database.yml backup"),
    ("/settings.json.bak", "JSON settings backup"),
    ("/appsettings.json.bak", ".NET appsettings backup"),
    ("/web.config.bak", "IIS web.config backup"),
]


def _filename_variants(path: str) -> list[str]:
    """Return backup variants of ``path`` (path + suffix and filename + suffix)."""
    out: list[str] = []
    # path + suffix: /foo/bar.html.bak
    for suf in BACKUP_SUFFIXES:
        out.append(path + suf)
    # filename-only suffix: /foo/.bar.html.swp (Vim swap style)
    last_slash = path.rfind("/")
    if last_slash >= 0:
        dir_ = path[: last_slash + 1]
        name = path[last_slash + 1:]
        for suf in BACKUP_SUFFIXES:
            out.append(dir_ + "." + name + suf)
    return out


@register
class BackupFilesModule(Module):
    name = "backup-files"
    categories = [Category.INFO_DISCLOSURE, Category.RECON]
    passive = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        discovered: list[str] = []
        # Always check root-level common backups.
        base = ctx.base_url.rstrip("/") + "/"
        candidates: list[tuple[str, str]] = []
        for path, label in HIGH_VALUE_FILES:
            candidates.append((path, label))
        # Also derive variants from crawled paths.
        seen_urls: set[str] = set()
        for u in ctx.urls[:30]:
            if u in seen_urls:
                continue
            seen_urls.add(u)
            parsed = urlparse(u)
            path = parsed.path
            if not path or path == "/":
                continue
            for variant in _filename_variants(path):
                candidates.append((variant, f"backup variant of {path}"))

        # De-dupe while preserving order.
        seen_paths: set[str] = set()
        unique: list[tuple[str, str]] = []
        for p, lbl in candidates:
            if p in seen_paths:
                continue
            seen_paths.add(p)
            unique.append((p, lbl))

        for path, label in unique[:120]:  # cap to stay bounded
            url = urljoin(base, path.lstrip("/"))
            resp = await ctx.client.get(url, follow_redirects=False)
            if resp.error and "DeniedTargetError" in (resp.error or ""):
                continue
            if resp.status != 200:
                continue
            body = resp.text or ""
            if not body.strip():
                continue
            # Quick content sniff: a real backup is non-trivially sized and
            # usually binary or contains source markers.
            looks_real = (
                len(body) > 64
                and (
                    any(s in body for s in ("<?php", "<?", "<html", "#!/", "---", "[Database]", "INSERT INTO", "CREATE TABLE"))
                    or len(body) > 1024  # large binary likely a real archive
                )
            )
            sev = Severity.HIGH if looks_real else Severity.MEDIUM
            findings.append(
                Finding(
                    category=Category.INFO_DISCLOSURE,
                    title=f"Backup / versioned file exposed: {path} ({label})",
                    severity=sev,
                    confidence="firm" if looks_real else "tentative",
                    url=resp.url,
                    description=(
                        "A backup / versioned copy of a file is publicly accessible. "
                        "These frequently contain source code, configuration, or "
                        "database dumps -- including secrets and credentials."
                    ),
                    evidence=f"GET {url} -> 200; content-type={resp.headers.get('content-type', '?')}; body[:200]={body[:200]!r}",
                    remediation="Remove backup files from webroot; never store them under the document root.",
                    cwe="CWE-538",
                    module=self.name,
                    verified=looks_real,
                )
            )
            discovered.append(path)
        ctx.recon["backup_files"] = discovered
        return findings
