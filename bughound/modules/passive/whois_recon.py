"""WHOIS / domain-registration recon via RDAP.

Sn1per's recon phase starts with "whois, ping, DNS" -- the basic ownership
and infrastructure facts every engagement needs. This module gets the WHOIS
equivalent over plain HTTPS using RDAP (the IETF-standardized, structured
successor to the WHOIS protocol: RFC 7482+), queried through ``rdap.org``'s
public bootstrap redirector so no legacy WHOIS TCP/43 client or per-TLD
server list is needed -- it goes through the same ``HttpClient`` (and
therefore the same denylist) as every other passive module.

Surfaces registrar, creation/expiry dates, nameservers, and registrant
organization (when the registry doesn't redact it) -- useful for attribution,
expiry-driven domain-hijack risk ("is this domain about to lapse?"), and
cross-referencing other domains registered by the same org.
"""

from __future__ import annotations

import json

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register
from ..recon_utils import register_domain_of


def _extract_event_date(events: list[dict], action: str) -> str | None:
    for ev in events or []:
        if ev.get("eventAction") == action:
            return ev.get("eventDate")
    return None


def _extract_registrant_org(entities: list[dict]) -> str | None:
    for ent in entities or []:
        roles = ent.get("roles") or []
        if "registrant" not in roles:
            continue
        vcard = ent.get("vcardArray")
        if not vcard or len(vcard) < 2:
            continue
        for field in vcard[1]:
            # vCard field shape: [name, params, type, value]
            if len(field) >= 4 and field[0] == "org":
                return str(field[3])
    return None


@register
class WhoisReconModule(Module):
    name = "whois-recon"
    categories = [Category.RECON]
    passive = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        registerable = register_domain_of(ctx.base_url)
        if not registerable or registerable in {"localhost", "127.0.0.1"}:
            ctx.log(f"whois-recon: skipping {ctx.base_url!r} (local / IP-only target)")
            return findings

        url = f"https://rdap.org/domain/{registerable}"
        ctx.log(f"whois-recon: querying RDAP for {registerable}")
        try:
            resp = await ctx.client.get(url, follow_redirects=True)
        except Exception as exc:  # noqa: BLE001
            ctx.log(f"whois-recon: RDAP query failed: {exc}")
            return findings

        if not resp.ok or resp.status != 200:
            ctx.log(f"whois-recon: no RDAP record for {registerable} (status {resp.status})")
            return findings

        try:
            data = json.loads(resp.text)
        except Exception:  # noqa: BLE001
            return findings

        registrar = None
        for ent in data.get("entities") or []:
            if "registrar" in (ent.get("roles") or []):
                vcard = ent.get("vcardArray")
                if vcard and len(vcard) > 1:
                    for field in vcard[1]:
                        if len(field) >= 4 and field[0] == "fn":
                            registrar = str(field[3])

        created = _extract_event_date(data.get("events"), "registration")
        expires = _extract_event_date(data.get("events"), "expiration")
        updated = _extract_event_date(data.get("events"), "last changed")
        nameservers = [ns.get("ldhName") for ns in data.get("nameservers") or [] if ns.get("ldhName")]
        registrant_org = _extract_registrant_org(data.get("entities"))
        statuses = data.get("status") or []

        whois_data = {
            "registrar": registrar,
            "created": created,
            "updated": updated,
            "expires": expires,
            "nameservers": nameservers,
            "registrant_org": registrant_org,
            "status": statuses,
        }
        ctx.recon["whois"] = {k: v for k, v in whois_data.items() if v}

        evidence_lines = [f"{k}: {v}" for k, v in whois_data.items() if v]
        if not evidence_lines:
            return findings

        findings.append(
            Finding(
                category=Category.RECON,
                title="Domain registration (WHOIS/RDAP) details",
                severity=Severity.INFO,
                confidence="firm",
                url=ctx.base_url,
                description=(
                    "RDAP registration data for the target's registerable domain -- "
                    "registrar, creation/expiry dates, nameservers, and (when not "
                    "redacted) registrant organization."
                ),
                evidence="\n".join(evidence_lines),
                remediation=(
                    "Confirm the domain is set to auto-renew and registrar-locked; an "
                    "expired domain can be re-registered by an attacker (full domain "
                    "hijack, including inherited inbound email trust)."
                ),
                references=["https://rdap.org/", "https://www.rfc-editor.org/rfc/rfc7482"],
                module=self.name,
                verified=True,
            )
        )
        return findings
