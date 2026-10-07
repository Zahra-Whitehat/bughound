"""Subdomain enumeration (passive CT-log lookup + active DNS brute force)
and dangling-CNAME subdomain-takeover detection.

Two independent discovery methods are merged, mirroring Sn1per's recon
phase:

1. **Certificate Transparency (crt.sh)** -- every TLS certificate ever
   issued for the target's registerable domain. Finds anything that was
   ever given a cert, including hosts the operator forgot about.
2. **Active DNS brute force** -- a curated wordlist of ~90 common hostnames
   resolved via DNS-over-HTTPS. Finds hosts that never had a logged
   certificate (internal tools, hosts behind a wildcard cert, etc.).

Both methods only ever talk to third-party infrastructure (crt.sh, public
DoH resolvers) -- **bughound never sends a single packet to a discovered
subdomain** unless the operator explicitly expands scope to it and re-scans.
This keeps the authorization gate meaningful: knowing a host exists is not
the same as being authorized to touch it.

On top of discovery, every resolved subdomain's CNAME is checked against a
catalog of third-party platforms known to be vulnerable to **subdomain
takeover** (a dangling CNAME still points at GitHub Pages / Heroku / S3 /
etc. after the operator decommissioned the resource there, letting anyone
register the same name on that platform and serve content under the
organization's hostname). Because confirming a takeover requires an HTTP
request to the *platform* the CNAME points at -- not the organization's own
infrastructure -- that confirmation step is left to the operator; bughound
flags the pattern and cites the exact check to run.
"""

from __future__ import annotations

import asyncio

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register
from ..recon_utils import (
    COMMON_SUBDOMAIN_WORDLIST,
    SUBDOMAIN_TAKEOVER_FINGERPRINTS,
    crt_sh_subdomains,
    doh_lookup,
    register_domain_of,
)

# Cap on how many resolved hosts get a CNAME-based takeover check, so a
# domain with thousands of CT-log entries can't blow up scan time.
MAX_TAKEOVER_CHECKS = 150
# Bound concurrent DoH lookups during brute force so we stay a good netizen
# toward the public resolvers (and the target's own authoritative DNS).
BRUTE_FORCE_CONCURRENCY = 20


@register
class SubdomainEnumModule(Module):
    name = "subdomain-enum"
    categories = [Category.RECON]
    passive = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        registerable = register_domain_of(ctx.base_url)
        if not registerable or registerable in {"localhost", "127.0.0.1"}:
            ctx.log(f"subdomain-enum: skipping {ctx.base_url!r} (local / IP-only target)")
            return findings

        ctx.log(f"subdomain-enum: querying crt.sh CT logs for *.{registerable}")

        async def fetch_ct(url: str) -> tuple[bool, str]:
            resp = await ctx.client.get(url, follow_redirects=True)
            return resp.ok, resp.text

        async def fetch_doh(url: str, headers: dict[str, str]) -> tuple[bool, str, dict[str, str]]:
            resp = await ctx.client.get(url, headers=headers, follow_redirects=True)
            return resp.ok, resp.text, resp.headers

        ct_subdomains: list[str] = []
        try:
            ct_subdomains = await crt_sh_subdomains(registerable, fetch_ct)
        except Exception as exc:  # noqa: BLE001
            ctx.log(f"subdomain-enum: crt.sh query failed: {exc}")

        ctx.log(
            f"subdomain-enum: brute-forcing {len(COMMON_SUBDOMAIN_WORDLIST)} "
            f"candidate hostnames under {registerable}"
        )
        brute_subdomains = await self._brute_force(registerable, fetch_doh)

        subdomains = sorted(set(ct_subdomains) | set(brute_subdomains))
        if not subdomains:
            ctx.log("subdomain-enum: no subdomains found via CT logs or brute force")
            return findings

        # Group: in-scope subdomains (operator authorized to test) vs
        # out-of-scope subdomains (visible but denied). Both are surfaced as
        # INFO -- knowing they exist is itself valuable -- but we mark the
        # denied ones so operators can expand scope if appropriate.
        in_scope = [s for s in subdomains if s == registerable or s.endswith("." + registerable)]
        ctx.recon["subdomains"] = in_scope

        findings.append(
            Finding(
                category=Category.RECON,
                title=f"Subdomain enumeration revealed {len(in_scope)} hostname(s)",
                severity=Severity.INFO,
                confidence="firm",
                url=ctx.base_url,
                description=(
                    f"Certificate Transparency logs ({len(set(ct_subdomains))} hit(s)) and "
                    f"active DNS brute force ({len(set(brute_subdomains))} hit(s)) together "
                    f"surfaced {len(in_scope)} distinct hostnames under {registerable}. Each "
                    "one is a potential attack-surface entry point and may be running "
                    "outdated software, exposed admin panels, or staging data."
                ),
                evidence="\n".join(in_scope[:80]),
                remediation=(
                    "Inventory all discovered hostnames; decommission forgotten subdomains "
                    "and re-scan the most interesting ones in scope."
                ),
                references=["https://crt.sh/", "https://certificate.transparency.dev/"],
                module=self.name,
                verified=True,
            )
        )

        takeover_findings = await self._check_takeovers(ctx, in_scope, fetch_doh)
        findings.extend(takeover_findings)
        return findings

    async def _brute_force(
        self,
        registerable: str,
        fetch_doh,
    ) -> list[str]:
        """Resolve the built-in wordlist against ``registerable`` via DoH."""

        sem = asyncio.Semaphore(BRUTE_FORCE_CONCURRENCY)

        async def resolve(label: str) -> str | None:
            name = f"{label}.{registerable}"
            async with sem:
                answers = await doh_lookup(name, "A", fetch_doh)
                if not answers:
                    answers = await doh_lookup(name, "CNAME", fetch_doh)
            return name if answers else None

        results = await asyncio.gather(
            *(resolve(label) for label in COMMON_SUBDOMAIN_WORDLIST),
            return_exceptions=True,
        )
        return [r for r in results if isinstance(r, str)]

    async def _check_takeovers(
        self,
        ctx: ScanContext,
        subdomains: list[str],
        fetch_doh,
    ) -> list[Finding]:
        """Flag subdomains whose CNAME still points at a third-party platform
        matching a known takeover fingerprint.

        Deliberately DNS-only: bughound never issues an HTTP request to a
        discovered subdomain here (that host is not necessarily in the
        operator's confirmed scope). The finding tells the operator exactly
        which third-party-platform response pattern confirms the takeover,
        so they can verify by hand or add the host to scope and re-scan.
        """

        sem = asyncio.Semaphore(BRUTE_FORCE_CONCURRENCY)
        candidates = subdomains[:MAX_TAKEOVER_CHECKS]

        async def check(sub: str) -> tuple[str, str, str] | None:
            async with sem:
                cnames = await doh_lookup(sub, "CNAME", fetch_doh)
            for cname in cnames:
                cname_l = cname.lower().rstrip(".")
                for service, suffixes, needles in SUBDOMAIN_TAKEOVER_FINGERPRINTS:
                    if any(suffix in cname_l for suffix in suffixes):
                        return sub, cname_l, service
            return None

        results = await asyncio.gather(*(check(s) for s in candidates), return_exceptions=True)
        hits = [r for r in results if isinstance(r, tuple)]
        if not hits:
            return []

        ctx.recon["subdomain_takeover_candidates"] = [
            {"subdomain": sub, "cname": cname, "service": service} for sub, cname, service in hits
        ]

        lines = [f"{sub}  ->  CNAME {cname}  (points at {service})" for sub, cname, service in hits]
        return [
            Finding(
                category=Category.MISCONFIG,
                title=f"Possible subdomain takeover: {len(hits)} dangling CNAME(s) found",
                severity=Severity.HIGH,
                confidence="tentative",
                url=ctx.base_url,
                description=(
                    "The following subdomains still carry a CNAME record pointing at a "
                    "third-party platform known to be susceptible to subdomain takeover "
                    "(GitHub Pages, Heroku, S3, Azure, etc.). If the resource behind that "
                    "CNAME was deleted/unclaimed on the provider's side, anyone can "
                    "register the same name there and serve arbitrary content -- "
                    "including phishing pages or stolen cookies -- under the "
                    "organization's own hostname. This is flagged from DNS evidence only; "
                    "bughound does not contact the subdomain itself (out of confirmed "
                    "scope). Confirm by visiting the host and checking for the "
                    "platform's \"not found / unclaimed\" page, or add the host to scope "
                    "and re-scan."
                ),
                evidence="\n".join(lines),
                remediation=(
                    "Remove the dangling DNS record, or re-claim the resource on the "
                    "third-party platform before anyone else does."
                ),
                references=[
                    "https://github.com/EdOverflow/can-i-take-over-xyz",
                    "https://0xpatrik.com/subdomain-takeover-basics/",
                ],
                cwe="CWE-350",
                module=self.name,
                verified=False,
            )
        ]
