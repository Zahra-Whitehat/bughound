"""Prototype pollution -- honest candidate detection + handoff payloads.

Client-side prototype pollution can only be *proven* in a browser (the
gadget executes after DOM load), which bughound deliberately does not
emulate. What CAN be established from the server side is:

1. **Server-side merge evidence** -- POSTing a JSON body containing
   ``{"__proto__": {"bhcanary": "bhpollute"}}`` to JSON endpoints; if the
   application echoes the polluted key/value somewhere in its response
   tree, a server-side recursive-merge sink is reachable (rare, but the
   strongest possible black-box evidence).
2. **Reflection candidates** -- query parameters of the classic shapes
   (``__proto__[x]=``, ``__proto__.x=``, ``constructor[prototype][x]=``)
   reflected into HTML/JS; these are *candidates* the payload-crafter
   hands to manual/client verification, exactly like the other
   honestly-labelled advisory findings in this project.

Findings are labelled accordingly: confirmed (server merge echo) vs
tentative (reflection candidate). Every request is a harmless GET/POST
carrying the canary only.
"""

from __future__ import annotations

import json
import random
import string

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register

MAX_TARGETS = 8


def _canary() -> tuple[str, str]:
    key = f"bh{ ''.join(random.choices(string.ascii_lowercase, k=8)) }"
    return key, f"pp{ ''.join(random.choices(string.ascii_lowercase + string.digits, k=8)) }"


def _query_variants(key: str, value: str) -> dict[str, str]:
    return {
        "bracket": f"__proto__[{key}]={value}",
        "dot": f"__proto__.{key}={value}",
        "constructor": f"constructor[prototype][{key}]={value}",
    }


@register
class PrototypePollutionModule(Module):
    name = "prototype-pollution"
    categories = [Category.XSS, Category.MISCONFIG]
    passive = False
    aggressive_required = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        key, value = _canary()

        # ---- 1. Server-side JSON merge sinks -----------------------------
        for rt in [t for t in ctx.request_targets if t.method.upper() == "POST"][:MAX_TARGETS]:
            payload = json.dumps({"__proto__": {key: value}})
            r = await ctx.client.post(
                rt.url,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            if not r.ok:
                continue
            if value in r.text or f'"{key}"' in r.text:
                findings.append(
                    Finding(
                        category=Category.MISCONFIG,
                        title=f"Server-side prototype-pollution sink reached via JSON body at {rt.url}",
                        severity=Severity.HIGH,
                        confidence="confirmed",
                        url=rt.url,
                        description=(
                            "A JSON body containing a __proto__ key caused the injected key/value "
                            "pair to surface in the application's response, indicating a recursive "
                            "merge that copies __proto__ into server-side objects. Depending on "
                            "gadgets this yields auth bypass, RCE or denial of service."
                        ),
                        evidence=f"POST {payload} -> response contains injected {key!r}: {r.text[:300]}",
                        request=f"POST {rt.url} (application/json) body: {payload}",
                        remediation=(
                            "Reject __proto__/constructor keys in JSON parsing; use "
                            "Object.create(null)-based maps; upgrade merge libraries."
                        ),
                        cwe="CWE-1321",
                        module=self.name,
                        verified=True,
                    )
                )
                break

        # ---- 2. Reflection candidates on GET targets ---------------------
        if not findings:
            for rt in [t for t in ctx.request_targets if t.method.upper() == "GET"][:MAX_TARGETS]:
                variant_payloads = _query_variants(key, value)
                for variant, fragment in variant_payloads.items():
                    k, _, v = fragment.partition("=")
                    url = rt.url
                    r = await ctx.client.get(url, params={**rt.params, k: v})
                    if not r.ok:
                        continue
                    if value in r.text:
                        findings.append(
                            Finding(
                                category=Category.XSS,
                                title=f"Prototype-pollution payload reflected at {rt.url} ({variant} syntax)",
                                severity=Severity.LOW,
                                confidence="tentative",
                                url=url,
                                description=(
                                    "A __proto__/constructor pollution payload in the query string is "
                                    "reflected into the response. Client-side pollution requires a DOM "
                                    "gadget and browser verification; this is an honestly-labelled "
                                    "candidate with a ready-to-test payload."
                                ),
                                evidence=(
                                    f"GET {url} with {k}={v} -> value {value!r} appears in the response. "
                                    "Manual client-side check: open the URL in a browser and probe "
                                    "Object.prototype in the console (Object.prototype.bhkey)."
                                ),
                                request=f"GET {url}?{k}={v}",
                                remediation=(
                                    "Sanitize parameter names beginning with __proto__/constructor; "
                                    "audit client gadgets that merge URL params into objects."
                                ),
                                cwe="CWE-1321",
                                module=self.name,
                                verified=False,
                            )
                        )
                        break
                if findings:
                    break
        return findings
