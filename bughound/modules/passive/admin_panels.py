"""Common admin-panel / management-interface discovery.

Probes for a curated list of well-known admin / management web paths
(/admin, /wp-admin, /phpmyadmin, /manager, /actuator, /solr, /jenkins, etc.).
A 200, 401, 403, or distinctive 30x is treated as evidence that the path
exists -- the operator can then investigate credentials / bypasses manually.

This is passive reconnaissance: every request is a plain GET with no payload,
respecting the denylist. Distinct from brute-forcing: we only check ~60 of
the most common management paths, not a wordlist.
"""

from __future__ import annotations

from urllib.parse import urljoin

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register

# (path, label, [distinctive body needles], expected_success_status)
ADMIN_PATHS: list[tuple[str, str, list[str], int]] = [
    # Generic
    ("/admin", "admin panel", ["login", "password", "admin"], 200),
    ("/admin/", "admin panel (with slash)", ["login", "password"], 200),
    ("/administrator", "administrator panel", ["login", "password"], 200),
    ("/admin/login", "admin login", ["login", "password"], 200),
    ("/manage", "management interface", [], 200),
    ("/manager", "manager (Tomcat)", ["tomcat", "manager"], 200),
    ("/manager/html", "Tomcat manager HTML", ["tomcat"], 200),
    ("/dashboard", "dashboard", [], 200),
    ("/control", "control panel", [], 200),
    ("/panel", "admin panel", [], 200),
    ("/cpanel", "cPanel", ["cpanel"], 200),
    ("/console", "web console", [], 200),
    ("/backoffice", "back office", [], 200),
    ("/backend", "backend", [], 200),
    ("/wp-admin/", "WordPress admin", ["wordpress", "wp-login"], 200),
    ("/wp-login.php", "WordPress login", ["wordpress", "loginform"], 200),
    ("/wp-content/", "WordPress content", [], 200),
    ("/phpmyadmin/", "phpMyAdmin", ["phpmyadmin"], 200),
    ("/phpMyAdmin/", "phpMyAdmin (CamelCase)", ["phpmyadmin"], 200),
    ("/pma/", "phpMyAdmin (pma alias)", ["phpmyadmin"], 200),
    ("/adminer.php", "Adminer", ["adminer"], 200),
    ("/adminer/", "Adminer (dir)", ["adminer"], 200),
    ("/dbadmin", "DB admin", [], 200),
    # Frameworks / runtimes
    ("/actuator", "Spring Boot Actuator", ["actuator", "_links"], 200),
    ("/actuator/health", "Spring Boot health", ["status"], 200),
    ("/actuator/env", "Spring Boot env (sensitive!)", [], 200),
    ("/actuator/heapdump", "Spring Boot heapdump (CRITICAL)", [], 200),
    ("/actuator/mappings", "Spring Boot mappings", [], 200),
    ("/jolokia", "Jolokia JMX", ["jolokia"], 200),
    ("/jmx-console", "JMX console (JBoss)", ["jmx"], 200),
    ("/web-console", "JBoss web console", [], 200),
    ("/ServerStatus", "Apache Server Status", ["Apache Server Status"], 200),
    ("/server-status", "Apache server-status", ["Apache Server Status"], 200),
    ("/server-info", "Apache server-info", ["Server Information"], 200),
    ("/_status", "status endpoint", [], 200),
    ("/_admin", "Elasticsearch admin", [], 200),
    ("/_cat", "Elasticsearch _cat API", [], 200),
    ("/_nodes", "Elasticsearch _nodes", [], 200),
    ("/solr/", "Apache Solr", ["solr"], 200),
    ("/solr/admin/", "Solr admin", ["solr"], 200),
    ("/jenkins/", "Jenkins CI", ["jenkins"], 200),
    ("/jenkins/script", "Jenkins script console (RCE!)", [], 200),
    ("/job/", "Jenkins job", [], 200),
    ("/gitlab/", "GitLab", ["gitlab"], 200),
    ("/user/login", "GitLab login", ["gitlab"], 200),
    ("/grafana/", "Grafana", ["grafana"], 200),
    ("/grafana/login", "Grafana login", ["grafana"], 200),
    ("/kibana/", "Kibana", ["kibana"], 200),
    ("/app/kibana", "Kibana (app)", ["kibana"], 200),
    ("/elasticsearch/", "Elasticsearch root", ["cluster_name"], 200),
    ("/adminer.php", "Adminer DB tool", ["adminer"], 200),
    ("/druid/", "Apache Druid", ["druid"], 200),
    ("/druid/indexer/", "Druid indexer (RCE risk)", [], 200),
    ("/nacos/", "Nacos", ["nacos"], 200),
    ("/eureka/", "Eureka", ["eureka"], 200),
    ("/config/", "Spring Cloud Config", [], 200),
    ("/swagger-ui/", "Swagger UI", ["swagger"], 200),
    ("/swagger-ui.html", "Swagger UI (html)", ["swagger"], 200),
    ("/v2/api-docs", "Swagger v2 api-docs", ["swagger", "api"], 200),
    ("/graphql", "GraphQL endpoint", ["data", "errors"], 200),
    ("/graphiql", "GraphiQL IDE", ["graphiql"], 200),
    ("/api/v1/swagger.json", "Swagger v1 JSON", ["swagger"], 200),
    ("/api/swagger.json", "Swagger JSON", ["swagger"], 200),
    ("/api-docs", "API docs", [], 200),
    ("/redoc", "ReDoc", ["redoc"], 200),
    ("/.env", "dotenv (already covered by info-disclosure)", ["="], 200),
    ("/config/database.yml", "Rails database.yml", [], 200),
    ("/config/secrets.yml", "Rails secrets.yml", [], 200),
    ("/debug", "debug endpoint", [], 200),
    ("/debug/vars", "Go expvar", [], 200),
    ("/debug/pprof", "Go pprof (info disclosure)", [], 200),
    ("/metrics", "Prometheus metrics", ["process_cpu"], 200),
    ("/prometheus", "Prometheus", ["process_cpu"], 200),
    ("/stats", "stats", [], 200),
    ("/healthcheck", "healthcheck", [], 200),
    ("/health", "health", [], 200),
    ("/status", "status", [], 200),
    ("/_next/data/", "Next.js data route", [], 200),
    ("/_nuxt/", "Nuxt asset dir", [], 200),
]


@register
class AdminPanelModule(Module):
    name = "admin-panels"
    categories = [Category.RECON, Category.INFO_DISCLOSURE]
    passive = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        discovered: list[str] = []
        base = ctx.base_url.rstrip("/") + "/"

        for path, label, needles, _ in ADMIN_PATHS:
            url = urljoin(base, path.lstrip("/"))
            resp = await ctx.client.get(url, follow_redirects=False)
            if resp.error and "DeniedTargetError" in (resp.error or ""):
                # The denylist is sacred: skip silently.
                continue
            if resp.status in (200, 401, 403, 407):
                # Distinguish true positives: 200 with a distinctive needle,
                # or any 401/403 (auth wall = path exists).
                body = resp.text or ""
                matched = any(n.lower() in body.lower() for n in needles) if needles else True
                if resp.status in (401, 403) or matched:
                    sev = (
                        Severity.HIGH
                        if any(s in label.lower() for s in ("heapdump", "script", "env", "RCE"))
                        else Severity.MEDIUM
                    )
                    findings.append(
                        Finding(
                            category=Category.INFO_DISCLOSURE,
                            title=f"Exposed management path: {label} ({resp.status})",
                            severity=sev,
                            confidence="firm" if resp.status == 200 else "tentative",
                            url=resp.url,
                            description=(
                                f"A common management / admin path ({path}) returned HTTP "
                                f"{resp.status}, indicating it exists. Investigate "
                                "authentication, default credentials, and known CVEs for "
                                "the corresponding product."
                            ),
                            evidence=f"GET {url} -> {resp.status}; body[:120]={body[:120]!r}",
                            remediation="Remove the management interface from public "
                                        "exposure; gate behind VPN / strong auth.",
                            cwe="CWE-538",
                            module=self.name,
                            verified=resp.status == 200,
                        )
                    )
                    discovered.append(f"{path} ({resp.status})")

        ctx.recon["admin_paths"] = discovered
        return findings
