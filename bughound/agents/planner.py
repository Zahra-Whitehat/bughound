"""Attack planner -- the recon-advisor / attack-planner persona.

After the RECON + CONFIG squads finish (phase 1), the planner reads the
structured reconnaissance data and writes the *attack plan* that steers
phase 2:

- **Focus areas** -- which attack surfaces look most promising (an
  exposed admin panel, a GraphQL schema, XML endpoints, WordPress
  fingerprints...), each with the reason and the squads/modules that
  work it.
- **Tech-specific guidance** -- Sn1per-style "what this stack implies"
  notes (WordPress -> wp-json/xmlrpc, ASP.NET -> viewstate, nginx
  -> off-by-slash aliases...).
- **WAF notes** -- which WAF is fronting the target and what that means
  for payload encoding (bughound's ``xml-entities`` bypass, slower
  pacing in stealth mode...).
- **Surface statistics** -- the numbers a triager wants at a glance.

The plan is deterministic (pure function of the recon dict), stored in
``ScanResult.plan`` and rendered as the report's "Attack plan" section.
It never sends requests and never changes scope: it is intelligence,
not action.
"""

from __future__ import annotations

from typing import Any

#: Tech-product -> note shown in the plan (Sn1per's "known issues to
#: try" instinct, reduced to safe, human-facing guidance).
TECH_NOTES: dict[str, str] = {
    "WordPress": "WordPress detected: /wp-json/wp/v2/users often leaks usernames; xmlrpc.php enables user enumeration and system.listMethods probes.",
    "Drupal": "Drupal detected: check /user/login, /core/install.php and REST/Web Services module exposure.",
    "Joomla": "Joomla detected: /administrator/ and com_* component parameters are the classic first stops.",
    "Shopify": "Shopify detected: review app proxy and webhook endpoints for unauthenticated access.",
    "Django": "Django detected: DEBUG=True pages (trailing-slash 404s) leak settings and URL patterns; look for /admin/ login.",
    "Laravel": "Laravel detected: /storage/, /.env and Telescope debugging endpoints deserve a look.",
    "Spring": "Spring Boot detected: /actuator/* endpoints (env, heapdump, mappings) are high-value if exposed.",
    "ASP.NET": "ASP.NET detected: examine ASPX error pages for stack traces; machine.keys and ViewState MAC issues are version-dependent.",
    "Next.js": "Next.js detected: /_next/data/ and middleware bypass CVEs depend on version; check for source-map leaks.",
    "Nuxt": "Nuxt detected: check /_nuxt/ build artifacts for embedded API routes and secrets.",
    "Express": "Express detected: verbose stack traces (X-Powered-By visible) often accompany /error dumps; enumerate routes via JS endpoints.",
    "phpMyAdmin": "phpMyAdmin fingerprinted: default-root attempts and setup.php exposure are worth one careful check each.",
    "Jenkins": "Jenkins detected: /script console and /asynchPeople/ anonymized access are the classic first checks.",
    "GitLab": "GitLab detected: /api/v4/users and public project registration settings may leak data.",
    "Grafana": "Grafana detected: anonymous access and /api/health dashboards are common quick wins.",
    "Kubernetes": "Kubernetes mentioned in page content: check for exposed kube APIs / dashboards on adjacent ports (via nmap, aggressive mode).",
    "React": "React SPA detected: secrets and unlisted API routes frequently live in the JS bundles -- see js-endpoints output.",
    "Vue": "Vue SPA detected: same as React -- JS bundles are the primary attack-surface source.",
}

WAF_ADVICE: dict[str, str] = {
    "Cloudflare": "Cloudflare fronting the target: many WAF rules inspect raw SQL keywords; bughound's xml-entities encoding (raw-body injection) and uncommon encodings are the bypass levers. Expect rate limiting -- keep concurrency low.",
    "AWS CloudFront": "CloudFront in front: origin misconfiguration (direct-to-origin access) is worth checking if origin hostnames leak via recon.",
    "AWS WAF": "AWS WAF detected: managed rule groups block common payloads; size/encoding quirks (multi-part, chunked) are the usual bypass surface.",
    "Akamai": "Akamai detected: aggressive rate limiting is likely; prefer fewer, high-signal probes (stealth/normal mode).",
    "Imperva Incapsula": "Incapsula detected: bot-mitigation will challenge non-browser agents; a real browser UA string matters.",
    "Sucuri": "Sucuri detected: virtual-patching blocks known-bad payloads; look for logic flaws rather than signature detection.",
    "F5 BIG-IP ASM": "F5 ASM detected: parameter tampering tolerance is narrow; test header-based attacks (host-header poisoning) which ASM rules cover less.",
    "Barracuda": "Barracuda detected: check for header smuggling opportunities around the proxy layer.",
    "Fortinet FortiWeb": "FortiWeb detected: known parser CVEs depend on version; keep payloads small and observe block pages.",
    "DDoS-Guard": "DDoS-Guard detected: expect geo/IP filtering; results may differ from a local run.",
}

FOCUS_MODULE_HINTS: dict[str, list[str]] = {
    "admin panel exposed": ["admin-panels", "default-logins"],
    "API documentation exposed": ["api-discovery", "graphql-hunter"],
    "GraphQL endpoint": ["graphql-hunter"],
    "XML endpoints": ["xxe-prober"],
    "backup files": ["backup-files", "secrets"],
    "source maps": ["sourcemap-exposure", "secrets"],
    "JWT tokens observed": ["jwt-attacks"],
    "host reflection": ["host-header-poison"],
    "login form": ["default-logins", "advisory"],
}


def build_attack_plan(recon: dict[str, Any], aggressive: bool) -> dict[str, Any]:
    """Derive the attack plan from phase-1 recon data (pure function)."""
    tech_stack: dict[str, list[str]] = recon.get("tech_stack") or {}
    waf = recon.get("waf")
    admin_paths = recon.get("admin_paths") or []
    api_docs = recon.get("api_docs") or []
    js_endpoints = recon.get("js_endpoints") or []
    subdomains = recon.get("subdomains") or []
    backup_files = recon.get("backup_files") or []
    sourcemaps = recon.get("sourcemaps") or []

    focus: list[dict[str, str]] = []
    if admin_paths:
        focus.append({
            "area": "admin panel exposed",
            "why": f"{len(admin_paths)} management path(s) respond: {', '.join(str(p) for p in admin_paths[:5])}",
        })
    if api_docs:
        focus.append({
            "area": "API documentation exposed",
            "why": f"{len(api_docs)} API doc endpoint(s) found: {', '.join(str(p) for p in api_docs[:5])}",
        })
    if backup_files:
        focus.append({
            "area": "backup files",
            "why": f"{len(backup_files)} backup/archive file(s) reachable -- highest-yield credential source",
        })
    if sourcemaps:
        focus.append({
            "area": "source maps",
            "why": f"{len(sourcemaps)} .map bundle(s) ship un-minified source (possible secrets)",
        })
    if any("graphql" in str(u).lower() for u in js_endpoints):
        focus.append({
            "area": "GraphQL endpoint",
            "why": "graphql paths referenced from JavaScript; introspection likely worth probing",
        })
    if subdomains:
        focus.append({
            "area": "subdomain perimeter",
            "why": f"{len(subdomains)} subdomain(s) resolved; takeover candidates are reported separately",
        })

    tech_notes: list[str] = []
    seen_products: set[str] = set()
    for products in tech_stack.values():
        for product in products or []:
            product = str(product)
            if product in TECH_NOTES and product not in seen_products:
                seen_products.add(product)
                tech_notes.append(f"[{product}] {TECH_NOTES[product]}")

    waf_note: dict[str, str] = {}
    if waf:
        advice = WAF_ADVICE.get(str(waf), "WAF detected: expect signature-based blocking; logic-flaw and encoding tricks are the levers.")
        waf_note = {"name": str(waf), "advice": advice}

    # Payload-technique hints the hunting squads should lean on.
    hints: list[str] = []
    if waf:
        hints.append("WAF in front: favour the raw-body xml-entities payload encoding and non-signature techniques (differential, timing).")
    if aggressive:
        hints.append("Aggressive mode: the exploit phase and attack chains will attempt impact proofs on every verified finding.")
    else:
        hints.append("Passive mode: no attack payloads are sent; re-run with --mode normal or --aggressive for active hunting.")
    if not js_endpoints:
        hints.append("No JS endpoints harvested: consider raising --max-urls/--max-depth for SPA targets.")

    return {
        "focus_areas": focus,
        "tech_notes": tech_notes,
        "waf": waf_note,
        "hints": hints,
        "surface_stats": {
            "subdomains": len(subdomains),
            "admin_paths": len(admin_paths),
            "api_docs": len(api_docs),
            "js_endpoints": len(js_endpoints),
            "backup_files": len(backup_files),
            "sourcemaps": len(sourcemaps),
        },
    }
