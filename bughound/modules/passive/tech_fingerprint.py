"""Technology-stack fingerprinting (Wappalyzer-style).

Inspects the landing-page response headers, cookies, and HTML to identify the
web server, language, framework, CMS, CDN, analytics, and JS libraries in use.
This is a passive check -- no payloads are sent.

Why this matters for recon: knowing the exact software / version lets the
operator cross-reference known CVEs, plan targeted exploitation paths, and
identify end-of-life components. Each identified product is also written to
``ctx.recon["tech_stack"]`` as ``{category: [products]}`` so the report renders
a clean stack overview.
"""

from __future__ import annotations

from collections import defaultdict
from urllib.parse import urljoin

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register
from ..recon_utils import TECH_FINGERPRINTS, favicon_hash


def _match(
    fingerprint: tuple[str, str, list[tuple[str, str]], str | None, str | None],
    headers_lower: dict[str, str],
    cookie_names: set[str],
    html_lower: str,
) -> bool:
    """True if the fingerprint's header / cookie / html needles all match."""
    _, _, header_needles, cookie_needle, html_needle = fingerprint
    for header, needle in header_needles:
        # An empty needle means "header is present at all".
        if header not in headers_lower:
            return False
        if needle and needle not in headers_lower[header].lower():
            return False
    if cookie_needle:
        if not any(cookie_needle.lower() in c.lower() for c in cookie_names):
            return False
    if html_needle:
        if html_needle.lower() not in html_lower:
            return False
    return True


@register
class TechFingerprintModule(Module):
    name = "tech-fingerprint"
    categories = [Category.RECON, Category.INFO_DISCLOSURE]
    passive = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        # Re-fetch the landing page so we get cookie headers too (the seed
        # headers captured by the crawler may be from a redirect).
        resp = await ctx.client.get(ctx.base_url, follow_redirects=True)
        if not resp.ok:
            return findings
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        set_cookie = resp.headers.get("set-cookie", "")
        # SimpleCookie handles the comma-separated form properly.
        from http.cookies import SimpleCookie

        cookie_names: set[str] = set()
        try:
            jar = SimpleCookie()
            jar.load(set_cookie)
            cookie_names = {m.lower() for m in jar.keys()}
        except Exception:  # noqa: BLE001
            pass
        html_lower = resp.text.lower()

        stack: dict[str, list[str]] = defaultdict(list)
        for fingerprint in TECH_FINGERPRINTS:
            category, product, *_ = fingerprint
            if _match(fingerprint, headers_lower, cookie_names, html_lower):
                if product not in stack[category]:
                    stack[category].append(product)

        ctx.recon["tech_stack"] = dict(stack)

        if not stack:
            findings.append(
                Finding(
                    category=Category.RECON,
                    title="No distinctive technology fingerprints detected",
                    severity=Severity.INFO,
                    confidence="tentative",
                    url=resp.url,
                    description=(
                        "The response did not match any of the known fingerprints in "
                        "the catalog. The site may be behind a custom reverse proxy, "
                        "use an uncommon stack, or actively strip identifying headers."
                    ),
                    evidence=(
                        f"server={headers_lower.get('server', '?')}; "
                        f"x-powered-by={headers_lower.get('x-powered-by', '?')}; "
                        f"cookies={sorted(cookie_names)}"
                    ),
                    remediation="Manually inspect the response to identify the stack.",
                    module=self.name,
                    verified=False,
                )
            )
            return findings

        # Emit one consolidated finding so the report stays readable.
        evidence_lines = [f"{cat}: {', '.join(prods)}" for cat, prods in sorted(stack.items())]
        findings.append(
            Finding(
                category=Category.INFO_DISCLOSURE,
                title=f"Technology stack identified ({sum(len(v) for v in stack.values())} components)",
                severity=Severity.INFO,
                confidence="firm",
                url=resp.url,
                description=(
                    "The response headers, cookies and HTML identify the underlying "
                    "web stack. Use this to drive targeted CVE research and "
                    "exploit-selection for the active phase."
                ),
                evidence="\n".join(evidence_lines),
                remediation=(
                    "Strip identifying response headers (Server, X-Powered-By, "
                    "X-AspNet-Version) and remove generator meta tags to reduce "
                    "passive fingerprinting surface."
                ),
                cwe="CWE-200",
                module=self.name,
                verified=True,
            )
        )

        favicon_finding = await self._fingerprint_favicon(ctx)
        if favicon_finding:
            findings.append(favicon_finding)
        return findings

    async def _fingerprint_favicon(self, ctx: ScanContext) -> Finding | None:
        """Hash /favicon.ico the way Shodan/Censys do, for a high-confidence
        cross-host pivot (``http.favicon.hash:<value>`` search).

        Default, never-replaced favicons are one of the strongest low-noise
        fingerprints available: unlike header strings they survive a reverse
        proxy stripping identifying headers, and a single hash often
        pinpoints an exact product/version (Jenkins, GitLab, a specific
        router admin UI, even a known malware C2 panel) rather than a
        generic "PHP" guess.
        """

        favicon_url = urljoin(ctx.base_url, "/favicon.ico")
        resp = await ctx.client.get(favicon_url, follow_redirects=True)
        if not resp.ok or resp.status != 200 or not resp.content:
            return None
        digest = favicon_hash(resp.content)
        if digest is None:
            return None

        ctx.recon.setdefault("favicon_hash", digest)
        return Finding(
            category=Category.RECON,
            title="Favicon hash fingerprint captured",
            severity=Severity.INFO,
            confidence="firm",
            url=favicon_url,
            description=(
                "The site's favicon was hashed using the same MurmurHash3 "
                "algorithm Shodan and Censys index under `http.favicon.hash`. "
                "Searching that hash on either platform surfaces every other "
                "exposed host serving the identical (usually default, "
                "never-replaced) icon -- often pinpointing the exact product "
                "or admin panel in use, and any sibling/related hosts the "
                "operator may not know are exposed."
            ),
            evidence=f"http.favicon.hash:{digest}  ({favicon_url})",
            remediation=(
                "Replace default/vendor favicons on anything internet-facing so "
                "automated favicon-hash pivoting can't fingerprint the product."
            ),
            references=["https://www.shodan.io/search?query=http.favicon.hash%3A" + str(digest)],
            module=self.name,
            verified=True,
        )
