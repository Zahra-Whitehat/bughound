"""Passive (non-intrusive) scanner modules.

These modules never send attack payloads; they inspect responses, headers,
cookies, TLS and well-known paths. They are safe to run against any target the
operator is authorized to test.

The package also hosts the **reconnaissance** modules: subdomain enumeration,
DNS lookups, technology fingerprinting, WAF detection, JS-endpoint harvesting,
admin-panel discovery, API documentation discovery, backup-file discovery,
source-map exposure, and email harvesting. These write structured
attack-surface data into ``ScanContext.recon`` so the report renders a single
Reconnaissance section alongside the findings.
"""

from . import (  # noqa: F401
    admin_panels,
    api_discovery,
    backup_files,
    cookies,
    cors,
    dns_recon,
    email_harvest,
    http_methods,
    info_disclosure,
    js_endpoints,
    robots_sitemap,
    secrets,
    security_headers,
    sourcemap_exposure,
    subdomain_enum,
    tech_fingerprint,
    tls,
    waf_detection,
    wayback_urls,
    whois_recon,
)
