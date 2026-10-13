"""JavaScript source-map exposure.

When a JS bundle is built with sourcemaps enabled, the minified file ships a
``//# sourceMappingURL=foo.js.map`` comment. If the .map file is also served,
an attacker can reconstruct the original (un-minified, with comments and
file paths) source code -- often including other unpublished modules, server
file layout, and sometimes inline secrets.

This module passively:
  * Fetches the seed HTML's same-origin ``<script src>`` files
  * Checks each for a ``sourceMappingURL`` comment
  * Where found, requests the .map file and reports the original file list

No payloads sent; passive string extraction only.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register

SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    port_a = pa.port or (443 if pa.scheme == "https" else 80)
    port_b = pb.port or (443 if pb.scheme == "https" else 80)
    return (pa.scheme, pa.hostname, port_a) == (pb.scheme, pb.hostname, port_b)


@register
class SourceMapModule(Module):
    name = "sourcemap-exposure"
    categories = [Category.INFO_DISCLOSURE, Category.RECON]
    passive = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        sourcemaps: list[str] = []
        # We do NOT cross-read ctx.recon -- run independently since modules
        # execute concurrently and ctx.recon may not yet be populated.
        soup = BeautifulSoup(ctx.seed_html, "html.parser")
        script_srcs = [urljoin(ctx.base_url, t["src"]) for t in soup.find_all("script", src=True)]
        same_origin = [s for s in script_srcs if _same_origin(s, ctx.base_url)]

        # Dedupe.
        seen: set[str] = set()
        unique = [s for s in same_origin if not (s in seen or seen.add(s))]

        for src in unique[:30]:
            resp = await ctx.client.get(src, follow_redirects=True)
            if not resp.ok or resp.status != 200:
                continue
            body = resp.text or ""
            m = SOURCEMAP_RE.search(body)
            if not m:
                continue
            map_url = urljoin(src, m.group(1))
            # Fetch the .map and verify it's a real source map.
            map_resp = await ctx.client.get(map_url, follow_redirects=True)
            if not map_resp.ok or map_resp.status != 200:
                continue
            try:
                map_data = json.loads(map_resp.text or "")
            except json.JSONDecodeError:
                continue
            sources = map_data.get("sources", [])
            sourcemaps.append(map_url)
            findings.append(
                Finding(
                    category=Category.INFO_DISCLOSURE,
                    title=f"Exposed source map: {map_url}",
                    severity=Severity.MEDIUM,
                    confidence="firm",
                    url=map_url,
                    description=(
                        f"The minified JavaScript file {src} ships a sourceMappingURL "
                        "comment and the .map file is publicly accessible. This leaks "
                        "the original (un-minified) source code, file paths, and "
                        "sometimes inline secrets or API keys not stripped from the "
                        "original source."
                    ),
                    evidence=(
                        f"sourcesCount={len(sources)}; sample sources: "
                        + ", ".join(sources[:8])
                    ),
                    remediation=(
                        "Disable sourcemap generation in production builds, or serve "
                        ".map files only on an internal / authenticated path."
                    ),
                    cwe="CWE-540",
                    module=self.name,
                    verified=True,
                )
            )

        # Merge with anything already in ctx.recon (js-endpoints may have added).
        existing = ctx.recon.get("sourcemaps") or []
        merged = sorted(set(list(existing) + sourcemaps))
        ctx.recon["sourcemaps"] = merged
        return findings
