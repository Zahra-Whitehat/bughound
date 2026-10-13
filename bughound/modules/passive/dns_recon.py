"""DNS reconnaissance via DNS-over-HTTPS (DoH).

Resolves A / AAAA / MX / TXT / NS / CAA / SOA records for the target's
registerable domain, and parses TXT records for SPF / DMARC posture. Uses the
public Cloudflare / Google DoH endpoints -- no ``dnspython`` dependency, no
system ``dig``/``nslookup`` binary required, and every request still goes
through the standard ``HttpClient`` so the denylist applies.

The findings surface infrastructure details (mail servers, nameservers,
certificate issuers allowed by CAA, email security posture) for situational
awareness; the structured data is also written to ``ctx.recon`` so the report
includes a clean Reconnaissance section.
"""

from __future__ import annotations

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register
from ..recon_utils import DNS_RECORD_TYPES, doh_lookup, register_domain_of


def _spf_findings(txt_records: list[str]) -> tuple[str | None, list[str]]:
    """Extract the SPF record + a list of posture notes (None if absent)."""
    spf_records = [t for t in txt_records if t.lower().startswith('"v=spf1') or t.lower().startswith("v=spf1")]
    spf = spf_records[0] if spf_records else None
    notes: list[str] = []
    if spf is None:
        notes.append("No SPF record published: the domain can be spoofed for email impersonation.")
    else:
        low = spf.lower()
        if "redirect=" not in low and "~all" not in low and "-all" not in low:
            notes.append("SPF record lacks a hard / soft fail-all clause; spoofed senders may pass.")
        if "+all" in low:
            notes.append("SPF record uses +all -- any host is authorized to send mail (very weak).")
        if "include:" not in low:
            notes.append("SPF record uses no include: clauses (may be too narrow or too wide).")
    return spf, notes


def _dmarc_findings(dmarc_records: list[str]) -> tuple[str | None, list[str]]:
    dmarc = dmarc_records[0] if dmarc_records else None
    notes: list[str] = []
    if dmarc is None:
        notes.append("No DMARC record published at _dmarc.<domain>: email-auth policy enforcement is missing.")
    else:
        low = dmarc.lower()
        if "p=none" in low:
            notes.append("DMARC policy is p=none (monitor only); no quarantine/reject enforcement.")
        if "p=" not in low:
            notes.append("DMARC record has no p= tag; behaviour is undefined.")
        if "rua=" not in low:
            notes.append("DMARC record has no rua= aggregate-report address; no visibility on failures.")
    return dmarc, notes


@register
class DnsReconModule(Module):
    name = "dns-recon"
    categories = [Category.RECON, Category.INFO_DISCLOSURE]
    passive = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        registerable = register_domain_of(ctx.base_url)
        # For local / IP-only targets there is no public DNS to query.
        if not registerable or registerable in {"localhost", "127.0.0.1"}:
            ctx.log(f"dns-recon: skipping {ctx.base_url!r} (no public DNS to query)")
            return findings
        ctx.log(f"dns-recon: querying DNS records for {registerable}")

        # Wrap HttpClient so the shared DoH helper stays decoupled.
        async def fetch(url: str, headers: dict[str, str]) -> tuple[bool, str, dict[str, str]]:
            resp = await ctx.client.get(url, headers=headers, follow_redirects=True)
            return resp.ok, resp.text, resp.headers

        records: dict[str, list[str]] = {}
        for rtype in DNS_RECORD_TYPES:
            ans = await doh_lookup(registerable, rtype, fetch)
            if ans:
                records[rtype] = ans

        # DMARC lives at _dmarc.<domain> as a TXT record.
        dmarc_answers = await doh_lookup(f"_dmarc.{registerable}", "TXT", fetch)
        # TXT records come back quoted -- strip outer quotes for readability.
        dmarc_records = [a.strip('"') for a in dmarc_answers if "v=dmarc1" in a.lower()]
        txt_records = [a.strip('"') for a in records.get("TXT", [])]

        # ---- emit findings ------------------------------------------------
        if "MX" in records:
            mx_summary = "; ".join(records["MX"][:8])
            findings.append(
                Finding(
                    category=Category.RECON,
                    title=f"Mail exchangers published for {registerable}",
                    severity=Severity.INFO,
                    confidence="firm",
                    url=ctx.base_url,
                    description=(
                        "MX records reveal the inbound mail infrastructure. These "
                        "hosts are valuable targets for SMTP-level probing (open relay, "
                        "user enumeration via VRFY/EXPN, STARTTLS downgrade)."
                    ),
                    evidence=mx_summary,
                    remediation="Restrict inbound SMTP to known peers; require STARTTLS.",
                    module=self.name,
                    verified=True,
                )
            )
        if "NS" in records:
            findings.append(
                Finding(
                    category=Category.RECON,
                    title=f"Authoritative nameservers for {registerable}",
                    severity=Severity.INFO,
                    confidence="firm",
                    url=ctx.base_url,
                    description="NS records reveal the DNS provider / hosting setup.",
                    evidence="; ".join(records["NS"][:8]),
                    remediation="Harden DNS provider (registrar lock, DNSSEC, MFA on DNS admin).",
                    module=self.name,
                    verified=True,
                )
            )
        if "CAA" in records:
            findings.append(
                Finding(
                    category=Category.RECON,
                    title="CAA records restrict certificate issuers",
                    severity=Severity.INFO,
                    confidence="firm",
                    url=ctx.base_url,
                    description=(
                        "CAA records limit which Certificate Authorities may issue "
                        "certificates for the domain -- a useful defence against "
                        "rogue issuance."
                    ),
                    evidence="; ".join(records["CAA"][:8]),
                    remediation="Verify the CAA allowlist matches your CA portfolio.",
                    module=self.name,
                    verified=True,
                )
            )

        spf, spf_notes = _spf_findings(txt_records)
        dmarc, dmarc_notes = _dmarc_findings(dmarc_records)
        email_posture_issues = spf_notes + dmarc_notes
        if email_posture_issues:
            sev = Severity.MEDIUM if not spf or not dmarc else Severity.LOW
            findings.append(
                Finding(
                    category=Category.MISCONFIG,
                    title="Email-auth posture weakness (SPF / DMARC)",
                    severity=sev,
                    confidence="firm",
                    url=ctx.base_url,
                    description=(
                        "The domain's SPF and/or DMARC configuration is missing or weak, "
                        "enabling email spoofing and phishing impersonation of the domain."
                    ),
                    evidence=(
                        f"SPF: {spf or '(none)'}\n"
                        f"DMARC: {dmarc or '(none)'}\n"
                        + "\n".join(f"- {n}" for n in email_posture_issues)
                    ),
                    remediation=(
                        "Publish a restrictive SPF (~all or -all), publish a DMARC "
                        "record starting at p=none with a rua= aggregate address, then "
                        "ramp to p=quarantine and p=reject as you gain confidence."
                    ),
                    cwe="CWE-290",
                    module=self.name,
                    verified=True,
                )
            )

        # ---- structured data for the report ------------------------------
        ctx.recon["dns_records"] = records
        ctx.recon["email_security"] = {
            "spf": spf,
            "dmarc": dmarc,
            "issues": email_posture_issues,
        }
        ctx.recon["registerable_domain"] = registerable
        return findings
