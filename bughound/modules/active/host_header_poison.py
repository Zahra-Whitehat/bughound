"""Host-header poisoning -- password-reset / cache-poisoning candidates.

The Host (and X-Forwarded-Host) header is frequently trusted to build
absolute URLs inside responses: password-reset links, canonical tags,
redirects, cookie domains and cached page variants. An attacker who can
control it rewrites those URLs to their own domain.

Detection is differential and reflection-specific:

1. Send the request with ``Host: bhhost-<canary>.example.com`` (and a
   second variant keeping Host intact but adding ``X-Forwarded-Host``).
2. A finding requires the *canary host* to appear in a meaningful sink:
   the Location header, an absolute link/canonical URL in the body, or a
   Set-Cookie Domain attribute.
3. The same request with the original headers must NOT contain the
   canary (it cannot by construction -- the repeat check instead proves
   determinism), and the reflection must survive a repeat request.

Impact narrative is tied to the sink type: Location/cookie reflections
read as redirect/cache-poisoning primitives; body-link reflections read
as password-reset-poisoning candidates.
"""

from __future__ import annotations

import random
import re
import string

from ...models import Category, Finding, Severity
from ..base import Module, RequestTarget, ScanContext, register

MAX_TARGETS = 8

#: Paths where host-trust bugs matter most (reset links, canonical URLs,
#: profile/redirect builders) -- probed first when the crawl offers more
#: candidates than the budget allows.
_PRIORITY_PATH_RE = re.compile(
    r"(reset|password|profile|account|register|confirm|redirect|callback|oauth|sso)", re.IGNORECASE
)


def _canary_host() -> str:
    return f"bhhost-{''.join(random.choices(string.ascii_lowercase + string.digits, k=8))}.evil.example"


def _classify(text: str, host: str, headers: dict[str, str]) -> list[str]:
    sinks: list[str] = []
    if headers.get("location", "").find(host) != -1:
        sinks.append("Location redirect header")
    for name, value in headers.items():
        if name.lower() == "set-cookie" and f"domain={host}" in value.lower():
            sinks.append("Set-Cookie domain attribute")
    for needle in (f'http://{host}', f'https://{host}', f'"{host}"', f"'{host}'"):
        if needle in text:
            sinks.append("absolute URL / JSON string in body")
            break
    return sinks


@register
class HostHeaderPoisonModule(Module):
    name = "host-header-poison"
    categories = [Category.MISCONFIG]
    passive = False
    aggressive_required = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        targets: list[RequestTarget] = [rt for rt in ctx.request_targets if rt.method.upper() == "GET"]
        seen_urls = {rt.url for rt in targets}
        # The crawler only records GET targets that carry parameters or set
        # cookies, but host-trust bugs live on plain pages too (password-reset
        # builders, canonical-link templates) -- so visited URLs join the
        # candidate pool as virtual targets.
        for u in ctx.urls:
            if u not in seen_urls:
                targets.append(RequestTarget(url=u, method="GET", params={}))
        if not targets:
            probe = RequestTarget(url=ctx.base_url, method="GET", params={})
            targets = [probe]
        # Auth/redirect-relevant paths first (reset links & canonical builders
        # are where host trust turns into real impact), then the rest.
        targets = sorted(
            targets, key=lambda rt: 0 if _PRIORITY_PATH_RE.search(rt.url) else 1
        )[:MAX_TARGETS]

        for rt in targets:
            host = _canary_host()
            # Variant 1: full Host override.
            r_host = await ctx.client.get(rt.url, params=rt.params, headers={"Host": host})
            # Variant 2: forwarded-host override (very common behind proxies).
            r_fwd = await ctx.client.get(
                rt.url, params=rt.params, headers={"X-Forwarded-Host": host}
            )
            if not (r_host.ok or r_fwd.ok):
                continue

            for variant, r in (("Host", r_host), ("X-Forwarded-Host", r_fwd)):
                if not r.ok:
                    continue
                sinks = _classify(r.text, host, r.headers)
                if not sinks:
                    continue
                # Repeat for determinism.
                if variant == "Host":
                    r2 = await ctx.client.get(rt.url, params=rt.params, headers={"Host": host})
                else:
                    r2 = await ctx.client.get(rt.url, params=rt.params, headers={"X-Forwarded-Host": host})
                if not r2.ok or not _classify(r2.text, host, r2.headers):
                    continue

                impact = (
                    "Password-reset links, canonical URLs, redirects or cached variants are "
                    "built from an attacker-controlled header. A crafted request poisons the "
                    "URL a victim receives -- the canonical password-reset-poisoning and web-"
                    "cache-poisoning primitive."
                    if "body" in " ".join(sinks) or "Location" in " ".join(sinks)
                    else "An attacker-controlled header is reflected into the response in a "
                    "security-relevant sink."
                )
                findings.append(
                    Finding(
                        category=Category.MISCONFIG,
                        title=f"Host-header reflection into {sinks[0].lower()} via {variant}",
                        severity=Severity.HIGH if ("body" in sinks[0] or "Location" in sinks[0]) else Severity.MEDIUM,
                        confidence="confirmed",
                        url=rt.url,
                        description=(
                            f"Supplying {variant}: {host} makes the application use that host "
                            f"in {', '.join(sinks)}. The reflection reproduced on a repeat "
                            "request, ruling out one-off cache artifacts."
                        ),
                        evidence=(
                            f"{variant}: {host} -> reflected in {', '.join(sinks)}\n"
                            f"Location: {r.headers.get('location', '(none)')}\n"
                            f"body excerpt: {r.text[:300]}"
                        ),
                        request=f"GET {rt.url} with {variant}: {host}",
                        impact=impact,
                        remediation=(
                            "Build absolute URLs from server-side configuration, never from "
                            "client-supplied Host/X-Forwarded-Host; allowlist the expected "
                            "host at the proxy; strip inbound X-Forwarded-* from untrusted "
                            "sources."
                        ),
                        cwe="CWE-644",
                        module=self.name,
                        verified=True,
                    )
                )
                break  # one variant per target is enough
        return findings
