"""Parse robots.txt, sitemap.xml, humans.txt and security.txt.

These well-known files are a goldmine for reconnaissance: ``robots.txt`` often
lists paths the operator *wants* to hide (which is exactly what an attacker
will probe first), ``sitemap.xml`` enumerates the entire intended URL space,
``humans.txt`` reveals team members / technology credits, and ``security.txt``
(RFC 9116) discloses the vulnerability disclosure policy and security contacts.

This module is strictly passive: it only GETs well-known paths and parses the
responses, never sends a payload. Discovered URLs are surfaced as INFO findings
and also written to ``ctx.recon`` so the operator gets a single deduplicated
attack-surface list in the report.
"""

from __future__ import annotations

from urllib.parse import urljoin
from xml.etree import ElementTree

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register
from ..recon_utils import register_domain_of

WELL_KNOWN_FILES: list[tuple[str, str]] = [
    # (path, label)
    ("/robots.txt", "robots.txt"),
    ("/sitemap.xml", "sitemap.xml"),
    ("/sitemap_index.xml", "sitemap index"),
    ("/humans.txt", "humans.txt"),
    ("/security.txt", "security.txt"),
    ("/.well-known/security.txt", "security.txt (RFC 9116)"),
    ("/.well-known/openid-configuration", "OpenID Connect discovery"),
    ("/.well-known/change-password", "change-password endpoint (RFC 8615)"),
    ("/.well-known/nodeinfo", "nodeinfo (ActivityPub)"),
    ("/.well-known/host-meta", "host-meta (XRD)"),
    ("/.well-known/apple-app-site-association", "Apple App Site Association"),
    ("/.well-known/assetlinks.json", "Android Asset Links"),
]


def _absolute(base: str, href: str) -> str:
    if not href:
        return ""
    if href.startswith(("http://", "https://")):
        return href.split("#")[0]
    return urljoin(base, href).split("#")[0]


def _same_origin_registerable(a: str, b: str) -> bool:
    ra, rb = register_domain_of(a), register_domain_of(b)
    return ra != "" and ra == rb


@register
class RobotsSitemapModule(Module):
    name = "robots-sitemap"
    categories = [Category.RECON, Category.INFO_DISCLOSURE]
    passive = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        discovered_urls: list[str] = []
        well_known_seen: list[str] = []
        robots_txt = ""
        security_txt = ""
        sitemap_urls: list[str] = []

        for path, label in WELL_KNOWN_FILES:
            url = urljoin(ctx.base_url.rstrip("/") + "/", path.lstrip("/"))
            resp = await ctx.client.get(url, follow_redirects=True)
            if not resp.ok or resp.status not in (200, 301, 302, 401, 403):
                continue
            # Treat 401/403 as "exists but protected" -- still useful signal.
            body = resp.text if resp.status == 200 else ""
            well_known_seen.append(f"{path} ({resp.status})")

            if label.startswith("robots.txt"):
                robots_txt = body
                findings.extend(self._parse_robots(ctx, resp.url, body, discovered_urls))
            elif label.startswith("sitemap"):
                sitemap_urls.extend(self._parse_sitemap(ctx, resp.url, body, discovered_urls))
            elif label.startswith("security.txt"):
                security_txt = body
                if body:
                    findings.append(self._security_finding(ctx, resp.url, body))
            elif label.startswith("humans.txt"):
                if body:
                    findings.append(self._humans_finding(ctx, resp.url, body))
            elif "OpenID" in label or "host-meta" in label or "nodeinfo" in label:
                if body:
                    findings.append(self._wellknown_finding(ctx, resp.url, label, body))

        # Persist to ctx.recon for the report's Reconnaissance section.
        ctx.recon.setdefault("robots_txt", robots_txt)
        ctx.recon.setdefault("sitemap_urls", sorted(set(sitemap_urls)))
        ctx.recon.setdefault("security_txt", security_txt)
        ctx.recon.setdefault("well_known_paths", well_known_seen)
        ctx.recon.setdefault("discovered_urls", sorted(set(discovered_urls)))
        # The engine doesn't read discovered_urls but a future crawler hook can.
        return findings

    # ---- parsers ----------------------------------------------------------

    def _parse_robots(
        self, ctx: ScanContext, base_url: str, body: str, sink: list[str]
    ) -> list[Finding]:
        findings: list[Finding] = []
        if not body:
            return findings
        # Surface Disallow / Allow / Crawl-delay / Sitemap directives.
        disallowed: list[str] = []
        sitemaps: list[str] = []
        for line in body.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or ":" not in line:
                continue
            directive, _, value = line.partition(":")
            directive = directive.strip().lower()
            value = value.strip()
            if directive == "disallow" and value:
                disallowed.append(value)
            elif directive == "allow" and value:
                disallowed.append("Allow: " + value)
            elif directive == "sitemap" and value:
                sitemaps.append(value)
                absu = _absolute(base_url, value)
                if absu:
                    sink.append(absu)
        if disallowed:
            findings.append(
                Finding(
                    category=Category.RECON,
                    title=f"robots.txt discloses {len(disallowed)} hidden path(s)",
                    severity=Severity.INFO,
                    confidence="firm",
                    url=base_url,
                    description=(
                        "robots.txt explicitly lists paths the operator wants hidden "
                        "from crawlers -- these are prime targets for further testing "
                        "since 'hidden' often implies sensitive."
                    ),
                    evidence="\n".join(disallowed[:40]),
                    remediation="Do not rely on robots.txt to enforce access control; "
                                "ensure hidden paths are protected server-side.",
                    module=self.name,
                    verified=True,
                )
            )
        return findings

    def _parse_sitemap(
        self, ctx: ScanContext, base_url: str, body: str, sink: list[str]
    ) -> list[str]:
        if not body:
            return []
        raw_urls: list[str] = []
        # Try XML first.
        try:
            root = ElementTree.fromstring(body)
            # Strip namespaces for resilience.
            for elem in root.iter():
                tag = elem.tag.split("}", 1)[-1].lower()
                if tag == "loc" and elem.text:
                    raw_urls.append(elem.text.strip())
        except ElementTree.ParseError:
            # Plain-text sitemap (one URL per line).
            for line in body.splitlines():
                line = line.strip()
                if line.startswith(("http://", "https://")):
                    raw_urls.append(line)
                elif line.startswith("/"):
                    raw_urls.append(line)
        # Resolve every URL to absolute against the sitemap URL (the URL the
        # sitemap was fetched from). Sitemap entries are often relative paths.
        absolute = [urljoin(base_url, u) for u in raw_urls if u]
        # Surface same-origin URLs only.
        same_origin = [u for u in absolute if _same_origin_registerable(u, ctx.base_url)]
        sink.extend(same_origin)
        return same_origin

    def _security_finding(self, ctx: ScanContext, url: str, body: str) -> Finding:
        contact = ""
        for line in body.splitlines():
            if line.lower().startswith("contact:"):
                contact = line.split(":", 1)[1].strip()
                break
        return Finding(
            category=Category.INFO_DISCLOSURE,
            title="security.txt published (RFC 9116)",
            severity=Severity.INFO,
            confidence="firm",
            url=url,
            description=(
                "A security.txt file is published, disclosing the vulnerability "
                f"disclosure policy and security contact ({contact or 'see file'})."
            ),
            evidence=body[:600],
            remediation="Keep security.txt up to date and verify the listed contact.",
            references=["https://www.rfc-editor.org/rfc/rfc9116.html"],
            module=self.name,
            verified=True,
        )

    def _humans_finding(self, ctx: ScanContext, url: str, body: str) -> Finding:
        return Finding(
            category=Category.INFO_DISCLOSURE,
            title="humans.txt published (team/tech disclosure)",
            severity=Severity.INFO,
            confidence="firm",
            url=url,
            description=(
                "humans.txt is published, which often credits the development team "
                "and the technologies used -- useful OSINT for attacker profiling."
            ),
            evidence=body[:600],
            remediation="Remove humans.txt if it discloses sensitive team info.",
            references=["https://humanstxt.org/"],
            module=self.name,
            verified=True,
        )

    def _wellknown_finding(
        self, ctx: ScanContext, url: str, label: str, body: str
    ) -> Finding:
        return Finding(
            category=Category.RECON,
            title=f"Well-known endpoint exposed: {label}",
            severity=Severity.INFO,
            confidence="firm",
            url=url,
            description=(
                f"A well-known discovery endpoint ({label}) is published. These "
                "endpoints reveal authentication, identity, or federation config "
                "useful for further attack-surface mapping."
            ),
            evidence=body[:400],
            remediation="Restrict well-known endpoints to authenticated callers if "
                        "they expose operational details.",
            module=self.name,
            verified=True,
        )
