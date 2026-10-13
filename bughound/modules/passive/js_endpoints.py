"""Endpoint harvesting from same-origin JavaScript files.

Pulls a sample of same-origin ``<script src>`` files and extracts API paths
and endpoints from the source using a curated set of regex patterns. This is
pure string extraction on already-delivered client content -- no payloads are
sent and no execution occurs.

Why this matters for recon: modern SPAs frequently embed their entire API
surface in shipped JS (REST paths, GraphQL queries, internal endpoints that
are never linked from HTML). Surfacing them gives the operator the full
attack-surface list before the active phase begins.
"""

from __future__ import annotations

import re
import warnings
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register

warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

# Endpoint patterns. We deliberately favour absolute-looking paths
# (leading /) and Swagger-style URLs to keep false positives low.
ENDPOINT_PATTERNS: list[re.Pattern[str]] = [
    # fetch/axios/get/post: (\"/api/...\") or ('/api/...')
    re.compile(r"""['"`](/api/[^'"`\s?#]+)"""),
    re.compile(r"""['"`](/v[0-9]+/[^'"`\s?#]+)"""),
    re.compile(r"""['"`](/rest/[^'"`\s?#]+)"""),
    re.compile(r"""['"`](/graphql)['"`]"""),
    re.compile(r"""['"`](/rpc/[^'"`\s?#]+)"""),
    re.compile(r"""['"`](/admin/[^'"`\s?#]+)"""),
    # Common path-shape: /word/word, /word/word/word
    re.compile(r"""['"`](/[a-z0-9_-]+/[a-z0-9_-]+(?:/[a-z0-9_-]+)?)['"`]"""),
]

# Source-map comments: //# sourceMappingURL=foo.js.map
SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    port_a = pa.port or (443 if pa.scheme == "https" else 80)
    port_b = pb.port or (443 if pb.scheme == "https" else 80)
    return (pa.scheme, pa.hostname, port_a) == (pb.scheme, pb.hostname, port_b)


@register
class JsEndpointsModule(Module):
    name = "js-endpoints"
    categories = [Category.RECON, Category.INFO_DISCLOSURE]
    passive = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        endpoints: set[str] = set()
        sourcemaps: set[str] = set()
        scripts_fetched = 0

        # Pull <script src> links from the landing page.
        soup = BeautifulSoup(ctx.seed_html, "html.parser")
        srcs: list[str] = []
        for tag in soup.find_all("script", src=True):
            src = urljoin(ctx.base_url, tag["src"])
            if _same_origin(src, ctx.base_url):
                srcs.append(src)
        # Also pick scripts from already-crawled URLs (cheap, cached) so we
        # get coverage beyond the landing page.
        for url in ctx.urls[:20]:
            try:
                resp = await ctx.client.get(url, follow_redirects=True)
            except Exception:  # noqa: BLE001
                continue
            if not resp.ok:
                continue
            page_soup = BeautifulSoup(resp.text, "html.parser")
            for tag in page_soup.find_all("script", src=True):
                src = urljoin(resp.url, tag["src"])
                if _same_origin(src, ctx.base_url):
                    srcs.append(src)
        # De-dupe while preserving order.
        seen_src: set[str] = set()
        unique_srcs = [s for s in srcs if not (s in seen_src or seen_src.add(s))]

        for src in unique_srcs[:25]:
            resp = await ctx.client.get(src, follow_redirects=True)
            if not resp.ok or resp.status != 200:
                continue
            scripts_fetched += 1
            body = resp.text
            for pat in ENDPOINT_PATTERNS:
                for m in pat.finditer(body):
                    path = m.group(1)
                    # Filter out obvious JS file paths and asset references.
                    if path.endswith((".js", ".css", ".png", ".jpg", ".svg", ".woff", ".ico")):
                        continue
                    endpoints.add(path)
            for m in SOURCEMAP_RE.finditer(body):
                sm = urljoin(src, m.group(1))
                sourcemaps.add(sm)

        ctx.recon["js_endpoints"] = sorted(endpoints)
        # Sourcemaps are surfaced separately by sourcemap_exposure.py, but
        # we record them here too so the recon section is complete even if
        # that module is disabled.
        existing = ctx.recon.get("sourcemaps") or []
        ctx.recon["sourcemaps"] = sorted(set(list(existing) + list(sourcemaps)))

        if endpoints:
            findings.append(
                Finding(
                    category=Category.RECON,
                    title=f"Extracted {len(endpoints)} endpoint path(s) from {scripts_fetched} JS file(s)",
                    severity=Severity.INFO,
                    confidence="firm",
                    url=ctx.base_url,
                    description=(
                        "Same-origin JavaScript files reference API / internal paths "
                        "that are not linked from HTML. These are valuable targets for "
                        "the active phase: many contain unauthenticated endpoints, "
                        "debug routes, or admin functionality."
                    ),
                    evidence="\n".join(sorted(endpoints)[:60]),
                    remediation="Minify and remove inline API references; serve debug "
                                "builds only on internal environments.",
                    cwe="CWE-200",
                    module=self.name,
                    verified=True,
                )
            )
        return findings
