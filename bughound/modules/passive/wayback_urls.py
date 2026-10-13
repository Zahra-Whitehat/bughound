"""Historical URL harvesting via the Wayback Machine's CDX API.

Sn1per and most modern recon toolchains (gau, waybackurls, katana) lean
heavily on archive.org's CDX index: every URL the Wayback Machine has ever
crawled for a domain, including parameterised endpoints, old API versions,
retired admin paths, and backup/config files that were briefly public years
ago and never got re-crawled by the live site's own crawler. This is often
the single highest-yield recon source for attack-surface discovery because
it remembers what the *current* site no longer links to.

Pure passive: this module only queries ``web.archive.org`` (through the
standard ``HttpClient``, so the denylist still applies) and never touches
the target itself. Discovered paths are surfaced for the operator to
triage/re-request manually, or fed into a follow-up scan; bughound does not
automatically fetch them (some may 404, some may still be live and worth a
closer look, some may be exactly the forgotten backup file an operator
wants to investigate by hand first).
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register
from ..recon_utils import register_domain_of

CDX_API = "https://web.archive.org/cdx/search/cdx"

# Extensions/paths worth calling out specially -- these are the classic
# "forgotten and still sitting in the archive" finds.
INTERESTING_RE = re.compile(
    r"\.(sql|bak|backup|old|zip|tar|tar\.gz|tgz|log|env|config|conf|ini|"
    r"yml|yaml|pem|key|pfx|p12|json|xml|swp)(\?|$)",
    re.IGNORECASE,
)
API_RE = re.compile(r"/(api|v[0-9]+|rest|graphql|admin|internal|debug)(/|$)", re.IGNORECASE)

MAX_URLS_FETCHED = 5000
MAX_URLS_SHOWN = 100


@register
class WaybackUrlsModule(Module):
    name = "wayback-urls"
    categories = [Category.RECON]
    passive = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        registerable = register_domain_of(ctx.base_url)
        if not registerable or registerable in {"localhost", "127.0.0.1"}:
            ctx.log(f"wayback-urls: skipping {ctx.base_url!r} (local / IP-only target)")
            return findings

        ctx.log(f"wayback-urls: querying CDX index for *.{registerable}")
        params = {
            "url": f"*.{registerable}/*",
            "output": "json",
            "collapse": "urlkey",
            "fl": "original",
            "limit": str(MAX_URLS_FETCHED),
        }
        try:
            resp = await ctx.client.get(CDX_API, params=params, follow_redirects=True)
        except Exception as exc:  # noqa: BLE001
            ctx.log(f"wayback-urls: CDX query failed: {exc}")
            return findings

        if not resp.ok or resp.status != 200 or not resp.text.strip():
            ctx.log(f"wayback-urls: no archived URLs for {registerable} (status {resp.status})")
            return findings

        try:
            rows = json.loads(resp.text)
        except Exception:  # noqa: BLE001
            return findings

        # First row is the header (["original"]) when results exist.
        urls = sorted({r[0] for r in rows[1:] if r})
        if not urls:
            ctx.log("wayback-urls: CDX index returned no URLs")
            return findings

        interesting = [u for u in urls if INTERESTING_RE.search(urlparse(u).path)]
        api_like = [u for u in urls if API_RE.search(urlparse(u).path)]

        ctx.recon["wayback_urls"] = urls[:MAX_URLS_SHOWN]
        ctx.recon["wayback_interesting_urls"] = interesting[:MAX_URLS_SHOWN]

        findings.append(
            Finding(
                category=Category.RECON,
                title=f"Wayback Machine archive reveals {len(urls)} historical URL(s)",
                severity=Severity.INFO,
                confidence="firm",
                url=ctx.base_url,
                description=(
                    f"archive.org's CDX index has crawled {len(urls)} distinct URLs under "
                    f"{registerable} over time, including {len(api_like)} that look like "
                    "API/admin/internal paths and "
                    f"{len(interesting)} that look like backup/config/credential-bearing "
                    "files. These may no longer be linked from the live site but could "
                    "still resolve, or reveal the shape of endpoints to probe directly."
                ),
                evidence="\n".join(urls[:MAX_URLS_SHOWN])
                + (f"\n... and {len(urls) - MAX_URLS_SHOWN} more" if len(urls) > MAX_URLS_SHOWN else ""),
                remediation=(
                    "Re-request interesting archived paths manually (never automatically "
                    "re-published without checking current status/sensitivity first); "
                    "ensure retired endpoints return 404/410 rather than stale content, "
                    "and confirm backup/config files are not still reachable."
                ),
                references=["https://web.archive.org/", "https://github.com/lc/gau"],
                module=self.name,
                verified=True,
            )
        )

        if interesting:
            findings.append(
                Finding(
                    category=Category.INFO_DISCLOSURE,
                    title=f"Wayback Machine has {len(interesting)} archived backup/config-looking URL(s)",
                    severity=Severity.MEDIUM,
                    confidence="tentative",
                    url=ctx.base_url,
                    description=(
                        "These archived URLs have extensions typically associated with "
                        "backups, configuration, credentials, or database dumps "
                        "(.sql, .bak, .env, .pem, etc.). The archive snapshot proves the "
                        "file was served publicly at some point; it is worth checking "
                        "whether it is still reachable today."
                    ),
                    evidence="\n".join(interesting[:MAX_URLS_SHOWN]),
                    remediation=(
                        "Verify none of these paths are still live; if any still exist, "
                        "remove them and audit how they became publicly reachable."
                    ),
                    cwe="CWE-530",
                    module=self.name,
                    verified=False,
                )
            )
        return findings
