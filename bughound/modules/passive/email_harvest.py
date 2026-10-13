"""Email harvesting from HTML and same-origin JS.

Collects email addresses from the landing page HTML and a sample of same-origin
JavaScript files. Useful for OSINT / phishing-simulation scoping, for
identifying internal naming conventions (e.g. firstname.lastname@company), and
for finding email addresses that may be reused as usernames on auth forms.

Passive: pure regex extraction on already-delivered content.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register

# Reasonably strict email regex: rejects most false positives (no consecutive
# dots, no leading/trailing dots, TLD >=2 chars).
EMAIL_RE = re.compile(
    r"\b[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
    r"@"
    r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b",
    re.IGNORECASE,
)

# Mailto: links in HTML are a strong signal -- parse them separately.
MAILTO_RE = re.compile(r"mailto:([^\"'\s?>]+)", re.IGNORECASE)

# Junk hosts we want to exclude from the report.
EXCLUDE_DOMAINS = {
    "sentry.io", "w3.org", "schema.org", "example.com", "example.org",
    "example.net", "github.com", "googleapis.com", "cloudflare.com",
}


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    port_a = pa.port or (443 if pa.scheme == "https" else 80)
    port_b = pb.port or (443 if pb.scheme == "https" else 80)
    return (pa.scheme, pa.hostname, port_a) == (pb.scheme, pb.hostname, port_b)


@register
class EmailHarvestModule(Module):
    name = "email-harvest"
    categories = [Category.RECON, Category.INFO_DISCLOSURE]
    passive = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        emails: set[str] = set()

        # 1. HTML mailto: links + free-text emails on landing page + crawled pages.
        corpus: list[tuple[str, str]] = [(ctx.base_url, ctx.seed_html)]
        for u in ctx.urls[:10]:
            if u == ctx.base_url:
                continue
            try:
                resp = await ctx.client.get(u, follow_redirects=True)
            except Exception:  # noqa: BLE001
                continue
            if resp.ok and "html" in resp.headers.get("content-type", ""):
                corpus.append((u, resp.text))

        # 2. Same-origin JS files.
        soup = BeautifulSoup(ctx.seed_html, "html.parser")
        for tag in soup.find_all("script", src=True):
            src = urljoin(ctx.base_url, tag["src"])
            if _same_origin(src, ctx.base_url):
                try:
                    resp = await ctx.client.get(src, follow_redirects=True)
                except Exception:  # noqa: BLE001
                    continue
                if resp.ok and resp.status == 200:
                    corpus.append((src, resp.text))

        for _src_url, text in corpus:
            for m in MAILTO_RE.finditer(text):
                email = m.group(1).strip().lower()
                if "@" in email:
                    emails.add(email)
            for m in EMAIL_RE.finditer(text):
                email = m.group(0).lower()
                domain = email.rsplit("@", 1)[-1]
                if domain in EXCLUDE_DOMAINS:
                    continue
                emails.add(email)

        ctx.recon["emails"] = sorted(emails)

        findings: list[Finding] = []
        if emails:
            findings.append(
                Finding(
                    category=Category.RECON,
                    title=f"Harvested {len(emails)} email address(es) from client content",
                    severity=Severity.INFO,
                    confidence="firm",
                    url=ctx.base_url,
                    description=(
                        "Email addresses were found in HTML and / or same-origin "
                        "JavaScript files. These are useful for OSINT, phishing "
                        "simulation, username enumeration, and may also indicate "
                        "internal naming conventions."
                    ),
                    evidence="\n".join(sorted(emails)[:30]),
                    remediation=(
                        "Avoid publishing individual email addresses in client "
                        "content; prefer a contact form or shared inbox."
                    ),
                    cwe="CWE-200",
                    module=self.name,
                    verified=True,
                )
            )
        return findings
