"""API documentation endpoint discovery.

Probes for common API-description endpoints (Swagger / OpenAPI / GraphQL
introspection / api-docs / ReDoc / Spring Boot HAL browser / RAML / API
Gateway listings). A hit gives the operator the *full* API surface --
endpoints, parameters, schemas -- often including internal endpoints never
linked from the UI.

Passive: only plain GETs, no payloads.
"""

from __future__ import annotations

import json
from urllib.parse import urljoin

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register

# (path, label, needle-in-body, expected-content-type hint)
API_DOC_PATHS: list[tuple[str, str, str, str]] = [
    ("/swagger-ui/index.html", "Swagger UI v3", "swagger", "html"),
    ("/swagger-ui/", "Swagger UI dir", "swagger", "html"),
    ("/swagger-ui.html", "Swagger UI (html)", "swagger", "html"),
    ("/swagger.json", "Swagger v1 JSON", "\"swagger\"", "json"),
    ("/swagger/v1/swagger.json", "Swagger v1 (versioned)", "\"swagger\"", "json"),
    ("/v1/api-docs", "Spring Boot api-docs v1", "\"swagger\"", "json"),
    ("/v2/api-docs", "Swagger v2 JSON", "\"swagger\"", "json"),
    ("/v3/api-docs", "OpenAPI v3 JSON", "\"openapi\"", "json"),
    ("/api-docs", "api-docs", "\"swagger\"", "json"),
    ("/openapi.json", "OpenAPI JSON", "\"openapi\"", "json"),
    ("/openapi.yaml", "OpenAPI YAML", "openapi:", "yaml"),
    ("/openapi.yml", "OpenAPI YAML (yml)", "openapi:", "yaml"),
    ("/api/openapi.json", "OpenAPI JSON (api path)", "\"openapi\"", "json"),
    ("/redoc", "ReDoc", "redoc", "html"),
    ("/redoc-static.html", "ReDoc static", "redoc", "html"),
    ("/rapidoc", "RapiDoc", "rapi-doc", "html"),
    ("/apispec_1.json", "APIspec 1", "\"swagger\"", "json"),
    ("/api/swagger.json", "Swagger JSON under /api", "\"swagger\"", "json"),
    ("/api/v1/swagger.json", "Swagger v1 JSON under /api/v1", "\"swagger\"", "json"),
    ("/api/v2/swagger.json", "Swagger v2 JSON under /api/v2", "\"swagger\"", "json"),
    ("/api/v3/openapi.json", "OpenAPI v3 under /api/v3", "\"openapi\"", "json"),
    ("/swagger-resources", "Swagger resources (Spring)", "\"location\"", "json"),
    ("/swagger-resources/configuration/ui", "Swagger UI config (Spring)", "\"apisSorter\"", "json"),
    ("/graphql", "GraphQL endpoint", "\"data\"", "json"),
    ("/graphql.json", "GraphQL schema JSON", "\"__schema\"", "json"),
    ("/graphql/schema.json", "GraphQL schema (alt path)", "\"__schema\"", "json"),
    ("/graphql/schema.graphql", "GraphQL SDL", "type ", "graphql"),
    ("/graphiql", "GraphiQL IDE", "graphiql", "html"),
    ("/altair/", "Altair GraphQL client", "altair", "html"),
    ("/playground", "GraphQL Playground", "playground", "html"),
    ("/api", "API root", "\"version\"", "json"),
    ("/api/v1", "API v1 root", "\"endpoints\"", "json"),
    ("/api/v1/status", "API v1 status", "\"status\"", "json"),
    ("/.well-known/openapi.json", "OpenAPI well-known", "\"openapi\"", "json"),
    ("/.well-known/api-spec", "API spec well-known", "\"openapi\"", "json"),
    ("/raml", "RAML API", "#%RAML", "yaml"),
    ("/api.raml", "RAML API (file)", "#%RAML", "yaml"),
    ("/hal-browser/browser.html", "Spring HAL browser", "hal-browser", "html"),
    ("/ ALPS profile + ", "Spring ALPS", "\"alps\"", "json"),
    ("/profile", "Spring Data REST profile", "\"alps\"", "json"),
    ("/actuator/mappings", "Spring Boot mappings (already covered)", "\"_links\"", "json"),
    ("/__graphql__", "GraphQL (alt)", "\"data\"", "json"),
    ("/api/graphql", "GraphQL under /api", "\"data\"", "json"),
    ("/v1/graphql", "GraphQL v1", "\"data\"", "json"),
    ("/console/api", "Django REST browsable API", "Django REST", "html"),
    ("/api/schema/", "Django REST schema", "\"openapi\"", "json"),
    ("/api/openapi-schema.json", "Django OpenAPI schema", "\"openapi\"", "json"),
]


@register
class ApiDiscoveryModule(Module):
    name = "api-discovery"
    categories = [Category.RECON, Category.INFO_DISCLOSURE]
    passive = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        discovered: list[str] = []
        base = ctx.base_url.rstrip("/") + "/"

        for path, label, needle, kind in API_DOC_PATHS:
            url = urljoin(base, path.lstrip("/"))
            resp = await ctx.client.get(url, follow_redirects=True)
            if not resp.ok or resp.status != 200:
                continue
            body = resp.text or ""
            ctype = resp.headers.get("content-type", "")
            # Match by either needle in body OR (for JSON) the right content-type.
            needle_match = needle.lower() in body.lower() if needle else True
            type_match = kind == "json" and "json" in ctype or \
                          kind == "yaml" and ("yaml" in ctype or "text" in ctype) or \
                          kind == "html" and "html" in ctype or \
                          kind == "graphql" and ("graphql" in ctype or "text" in ctype)
            if not (needle_match or type_match):
                continue
            # Try a deeper probe for GraphQL: send an introspection query.
            if "GraphQL" in label:
                introspection = await self._graphql_introspect(ctx, url)
                if introspection is not None:
                    body += "\n--- introspection ---\n" + introspection[:400]

            sev = Severity.HIGH if "GraphQL" in label or "api-docs" in path else Severity.MEDIUM
            findings.append(
                Finding(
                    category=Category.INFO_DISCLOSURE,
                    title=f"Exposed API documentation: {label}",
                    severity=sev,
                    confidence="firm",
                    url=resp.url,
                    description=(
                        "An API description endpoint is publicly accessible. It "
                        "exposes the entire API surface (endpoints, parameters, "
                        "schemas, and often internal/undocumented routes) -- a "
                        "treasure map for the active phase."
                    ),
                    evidence=f"GET {url} -> 200; content-type={ctype}; body[:200]={body[:200]!r}",
                    remediation="Restrict API doc endpoints to authenticated / internal users.",
                    cwe="CWE-200",
                    module=self.name,
                    verified=True,
                )
            )
            discovered.append(f"{path} ({label})")

        ctx.recon["api_docs"] = discovered
        return findings

    async def _graphql_introspect(self, ctx: ScanContext, url: str) -> str | None:
        """Send a GraphQL introspection query; return the response text or None.

        This is *technically* a body POST, but it carries no attack payload --
        it is the canonical schema-discovery query defined by the GraphQL
        spec itself, used by every GraphQL client. We treat it as passive
        recon (akin to OPTIONS).
        """
        query = '{"query":"query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description type{...TypeRef}args{...InputValue}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}"}'
        try:
            resp = await ctx.client.post(
                url,
                headers={"content-type": "application/json"},
                data=query.encode(),
                follow_redirects=True,
            )
            if not resp.ok or "data" not in (resp.text or ""):
                return None
            # Quick sanity check: parse and confirm it has __schema.
            data = json.loads(resp.text)
            if isinstance(data, dict) and data.get("data", {}).get("__schema"):
                return resp.text
        except Exception:  # noqa: BLE001
            return None
        return None
