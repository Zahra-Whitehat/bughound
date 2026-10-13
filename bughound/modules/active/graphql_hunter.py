"""GraphQL hunting -- the graphql-hunter persona.

Probes common GraphQL paths and decides from real responses:

- **Endpoint discovery** -- ``POST {"query":"{ __typename }"}`` (and a
  GET variant) returning ``{"data": {"__typename": ...}}`` is a live
  GraphQL endpoint.
- **Introspection enabled** -- a full introspection query returning
  ``__schema`` discloses the entire API surface (types, fields, resolvers'
  private naming, sometimes comments). Evidence includes the type count
  and a sample of type names.
- **GET-based introspection** -- some deployments accept introspection
  over GET, which also opens plain-link exfiltration (logs, Referer).
- **Field suggestions** -- a deliberately misspelled query answered with
  ``Did you mean '...'`` lets an attacker enumerate the schema even when
  introspection is disabled.

All probes are read-only GraphQL queries; nothing is mutated. Paths are
bounded (``MAX_PATHS``) and every request flows through the denylist-
guarded client.
"""

from __future__ import annotations

import json
import re

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register

CANDIDATE_PATHS = [
    "/graphql",
    "/api/graphql",
    "/graphiql",
    "/graphql/console",
    "/v2/graphql",
    "/gql",
    "/query",
    "/apollo",
    "/index.php?graphql=true",
]

INTROSPECTION_QUERY = json.dumps({
    "query": "{ __schema { types { name } queryType { name } } }",
})
TYPENAME_QUERY = json.dumps({"query": "{ __typename }"})
TYPO_QUERY = json.dumps({"query": "{ __typname }"})

MAX_PATHS = 8


@register
class GraphqlHunterModule(Module):
    name = "graphql-hunter"
    categories = [Category.INFO_DISCLOSURE, Category.MISCONFIG]
    passive = False
    aggressive_required = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        base = ctx.base_url.rstrip("/")
        # De-duplicate: operator/designated targets may share the base.
        tried: set[str] = set()

        for path in CANDIDATE_PATHS[:MAX_PATHS]:
            url = base + path
            if url in tried:
                continue
            tried.add(url)
            if ctx.client._blocked and ctx.client._blocked(url):
                continue

            # 1. Endpoint liveness: POST __typename.
            r = await ctx.client.post(
                url,
                data=TYPENAME_QUERY,
                headers={"Content-Type": "application/json"},
            )
            if not r.ok:
                continue
            try:
                body = json.loads(r.text)
            except (ValueError, TypeError):
                # GraphiQL HTML console is also a discovery hit.
                if "graphiql" in r.text.lower():
                    findings.append(self._finding(
                        url, "GraphQL console (GraphiQL) exposed",
                        Severity.LOW, "tentative",
                        "An interactive GraphQL console is reachable; it eases manual exploration for anyone with the URL.",
                        f"GraphiQL HTML markers at {url}",
                    ))
                continue
            data = body.get("data") if isinstance(body, dict) else None
            if not (isinstance(data, dict) and "__typename" in data):
                continue

            # Live endpoint confirmed. 2. Introspection over POST.
            intro = await ctx.client.post(
                url, data=INTROSPECTION_QUERY, headers={"Content-Type": "application/json"}
            )
            try:
                intro_body = json.loads(intro.text)
            except (ValueError, TypeError):
                intro_body = {}
            types = (
                intro_body.get("data", {}).get("__schema", {}).get("types", [])
                if isinstance(intro_body, dict) else []
            )
            if types:
                names = [t.get("name", "") for t in types if isinstance(t, dict)]
                findings.append(self._finding(
                    url, f"GraphQL introspection enabled ({len(names)} types disclosed)",
                    Severity.MEDIUM, "confirmed",
                    "The GraphQL schema is fully introspectable: object types, fields and "
                    "relationships are disclosed, giving an attacker a complete API map "
                    "and letting them target undocumented or admin-only operations.",
                    f"introspection returned {len(names)} types incl. "
                    f"{', '.join(sorted(set(n for n in names if n and not n.startswith('__')))[:8])}",
                    request=f"POST {url} (application/json) body: {INTROSPECTION_QUERY}",
                    cwe="CWE-200",
                ))
                # 3. GET-based introspection (also enables link/Referer leaks).
                g = await ctx.client.get(url, params={"query": INTROSPECTION_QUERY})
                try:
                    g_ok = "__schema" in json.loads(g.text).get("data", {})
                except (ValueError, TypeError):
                    g_ok = False
                if g_ok:
                    findings.append(self._finding(
                        url, "GraphQL introspection also allowed over GET",
                        Severity.LOW, "confirmed",
                        "Introspection succeeds over plain GET, so full schema URLs can leak "
                        "into browser history, proxy logs and Referer headers.",
                        f"GET {url}?query={INTROSPECTION_QUERY[:60]}... returned __schema",
                    ))
            else:
                # 4. Field suggestions (works even with introspection off).
                typo = await ctx.client.post(
                    url, data=TYPO_QUERY, headers={"Content-Type": "application/json"}
                )
                if re.search(r"did you mean", typo.text, re.IGNORECASE):
                    findings.append(self._finding(
                        url, "GraphQL field suggestions enabled (schema enumeration possible)",
                        Severity.LOW, "confirmed",
                        "Validation errors include 'Did you mean ...' suggestions, which let "
                        "attackers enumerate the schema even with introspection disabled.",
                        f"response: {typo.text[:200]}",
                        cwe="CWE-203",
                    ))

            if findings:
                break  # one confirmed endpoint is enough per scan
        return findings

    @staticmethod
    def _finding(url, title, severity, confidence, description, evidence,
                 request="", cwe=""):
        return Finding(
            category=Category.MISCONFIG,
            title=title,
            severity=severity,
            confidence=confidence,
            url=url,
            description=description,
            evidence=evidence,
            request=request,
            remediation=(
                "Disable introspection in production, silence field suggestions, and "
                "gate GraphQL operations with depth/complexity limits and authz rules."
            ),
            cwe=cwe or "CWE-16",
            module="graphql-hunter",
            verified=confidence == "confirmed",
        )
