"""Shared helpers for the passive recon modules.

These utilities are intentionally dependency-free: they go through the same
``HttpClient`` the rest of bughound uses (so the denylist still applies) and
fall back to public DNS-over-HTTPS (DoH) resolvers for DNS record lookups so
the agent does not need ``dnspython`` or system ``dig``/``nslookup`` binaries.

All functions are network-tolerant: on any error they return an empty / None
value rather than raising, so a flaky resolver never aborts a scan.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Awaitable, Callable
from urllib.parse import urlparse

# Public DoH endpoints. We try them in order; the first that returns a valid
# JSON answer wins. Both Cloudflare and Google are free, fast, and CORS-open.
DOH_ENDPOINTS: list[str] = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
]

# DNS record types we care about for recon. ``CAA`` reveals certificate
# issuers allowed for the domain (useful for subdomain-takeover triage);
# ``SOA`` reveals the primary nameserver; ``MX``/``TXT`` reveal mail posture
# (SPF/DMARC live in TXT records).
DNS_RECORD_TYPES: list[str] = ["A", "AAAA", "MX", "TXT", "NS", "CAA", "SOA"]

# Used only by active subdomain brute-force / takeover detection (not part of
# the standard per-domain DNS_RECORD_TYPES sweep, which stays small/fast).
CNAME_RECORD_TYPE = "CNAME"


def register_domain_of(url: str) -> str:
    """Return the eTLD+1 (registerable domain) for ``url``.

    Falls back to the bare hostname when no public suffix list is available --
    correct for the common single-label / private-DNS case bughound is usually
    pointed at. Examples: ``https://api.www.example.com`` -> ``example.com``;
    ``http://localhost:8081`` -> ``localhost``.
    """

    host = (urlparse(url if "://" in url else f"http://{url}").hostname or url).lower()
    if host in {"localhost", "127.0.0.1", "::1"} or re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        return host
    parts = host.split(".")
    # Heuristic eTLD+1: last two labels (works for example.com, fails for
    # co.uk-style TLDs; acceptable trade-off for a dependency-free impl).
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def is_same_registerable(subhost: str, registerable: str) -> bool:
    """True if ``subhost`` ends in ``.registerable`` or equals it."""
    subhost = subhost.lower().rstrip(".")
    registerable = registerable.lower()
    return subhost == registerable or subhost.endswith("." + registerable)


async def doh_lookup(
    name: str,
    rtype: str,
    fetch: Callable[[str, dict[str, str]], Awaitable[tuple[bool, str, dict[str, str]]]],
) -> list[str]:
    """Resolve ``name`` / ``rtype`` via DNS-over-HTTPS.

    ``fetch(url, headers) -> (ok, body, headers)`` is the HTTP primitive the
    caller supplies (normally ``HttpClient.request`` wrapped in a shim) so this
    helper stays decoupled from the concrete HTTP client and the denylist
    keeps applying transparently.

    Returns a list of stringified answers (e.g. IPs for A, ``10 mail.example.com.``
    for MX, raw TXT strings). Empty on any failure.
    """

    # Cloudflare requires the DoH JSON accept header; Google accepts plain JSON.
    # We attempt Cloudflare first (POST is also accepted, but GET with ?type= is
    # the simplest path), then Google's resolve endpoint as a fallback.
    for endpoint in DOH_ENDPOINTS:
        try:
            if "cloudflare" in endpoint:
                url = f"{endpoint}?name={name}&type={rtype}"
                headers = {"accept": "application/dns-json"}
            else:  # Google
                url = f"{endpoint}?name={name}&type={rtype}"
                headers = {"accept": "application/dns-json"}
            ok, body, _ = await fetch(url, headers)
            if not ok or not body:
                continue
            data = json.loads(body)
            answers = data.get("Answer") or []
            return [str(a.get("data", "")) for a in answers if a.get("data")]
        except Exception:  # noqa: BLE001 - never raise from recon helpers
            continue
    return []


async def crt_sh_subdomains(
    domain: str,
    fetch: Callable[[str], Awaitable[tuple[bool, str]]],
) -> list[str]:
    """Query crt.sh's Certificate Transparency log for subdomains of ``domain``.

    ``fetch(url) -> (ok, body)`` is supplied by the caller (HttpClient wrapper).

    Returns a de-duplicated list of subdomain hostnames. Empty on any failure
    (crt.sh is sometimes slow / rate-limited; we treat that as "no data" rather
    than an error so the rest of the scan proceeds).
    """

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        ok, body = await fetch(url)
        if not ok or not body:
            return []
        # crt.sh returns a JSON array of objects with a ``name_value`` field
        # containing one or more newline-separated SAN entries.
        entries = json.loads(body)
    except Exception:  # noqa: BLE001
        return []

    found: set[str] = set()
    for entry in entries:
        names = entry.get("name_value", "") if isinstance(entry, dict) else ""
        for name in str(names).splitlines():
            name = name.strip().lstrip("*.").lower()
            if name and is_same_registerable(name, domain):
                found.add(name)
    return sorted(found)


# A small, curated fingerprint catalog inspired by Wappalyzer. Each entry is
# (category, product-name, list-of-header-key-needle triples, optional-cookie-
# name-needle, optional-html-needle). Keep entries tolerant to false positives:
# prefer distinctive strings over generic ones.
TECH_FINGERPRINTS: list[tuple[str, str, list[tuple[str, str]], str | None, str | None]] = [
    # (category, product, [(header, needle)], cookie, html_needle)
    ("Web server", "nginx", [("server", "nginx")], None, None),
    ("Web server", "Apache", [("server", "apache")], None, None),
    ("Web server", "Microsoft IIS", [("server", "microsoft-iis")], None, None),
    ("Web server", "LiteSpeed", [("server", "litespeed")], None, None),
    ("Language", "PHP", [("x-powered-by", "php")], "PHPSESSID", None),
    ("Language", "ASP.NET", [("x-powered-by", "asp.net"), ("x-aspnet-version", "")], "ASP.NET_SessionId", None),
    ("Language", "Java", [("x-powered-by", "jsp"), ("server", "tomcat")], "JSESSIONID", None),
    ("Language", "Python", [("server", "gunicorn"), ("server", "uvicorn"), ("server", "werkzeug")], None, None),
    ("Language", "Ruby", [("server", "ruby"), ("x-powered-by", "ruby")], None, None),
    ("Language", "Node.js", [("x-powered-by", "express")], None, None),
    ("Framework", "Django", [("x-frame-options", "")], "csrftoken", 'name="csrfmiddlewaretoken"'),
    ("Framework", "Ruby on Rails", [("x-powered-by", "rails")], "_rails_session", 'name="authenticity_token"'),
    ("Framework", "Laravel", [], "laravel_session", None),
    ("Framework", "Symfony", [], None, "symfony"),
    ("Framework", "Spring", [], "JSESSIONID", None),
    ("Framework", "ASP.NET MVC", [("x-aspnetmvc-version", "")], None, None),
    ("Framework", "Express", [("x-powered-by", "express")], None, None),
    ("Framework", "Next.js", [("x-powered-by", "next")], None, "__next"),
    ("Framework", "Nuxt", [("x-powered-by", "nuxt")], None, "__nuxt"),
    ("CMS", "WordPress", [], "wordpress", 'content="WordPress'),
    ("CMS", "Drupal", [], None, 'name="form_build_id"'),
    ("CMS", "Joomla", [], None, "joomla"),
    ("CMS", "Ghost", [("x-ghost-cache-status", "")], "ghost-admin-api-session", None),
    ("CMS", "Magento", [], None, "Mage.Cookies"),
    ("CMS", "Shopify", [("x-shopify-stage", ""), ("x-shopid", "")], None, "cdn.shopify.com"),
    ("CMS", "Hugo", [], None, 'meta name="generator" content="Hugo'),
    ("CMS", "Jekyll", [], None, 'meta name="generator" content="Jekyll'),
    ("E-commerce", "WooCommerce", [], None, "woocommerce"),
    ("Analytics", "Google Analytics", [], None, "google-analytics.com"),
    ("Analytics", "Google Tag Manager", [], None, "googletagmanager.com"),
    ("Analytics", "Matomo/Piwik", [], None, "matomo"),
    ("Analytics", "Mixpanel", [], None, "mixpanel"),
    ("CDN", "Cloudflare", [("server", "cloudflare"), ("cf-ray", "")], "__cf_bm", None),
    ("CDN", "Fastly", [("x-served-by", "cache-"), ("x-fastly", "")], None, None),
    ("CDN", "Akamai", [("x-akamai-transformed", ""), ("x-akamai-request-id", "")], None, None),
    ("CDN", "AWS CloudFront", [("via", "cloudfront"), ("x-amz-cf-id", "")], None, None),
    ("CDN", "Vercel", [("server", "vercel"), ("x-vercel-id", "")], None, None),
    ("CDN", "Netlify", [("server", "netlify")], None, None),
    ("CDN", "GitHub Pages", [("server", "github.io")], None, None),
    ("OS", "Ubuntu", [("server", "ubuntu")], None, None),
    ("OS", "Debian", [("server", "debian")], None, None),
    ("Database proxy", "phpMyAdmin", [], None, "phpmyadmin"),
    ("Database proxy", "Adminer", [], None, "adminer"),
    ("Reverse proxy", "Traefik", [("server", "traefik")], None, None),
    ("Reverse proxy", "HAProxy", [("server", "haproxy")], None, None),
    ("Reverse proxy", "Envoy", [("server", "envoy")], None, None),
    ("Reverse proxy", "Caddy", [("server", "caddy")], None, None),
    ("Container orchestrator", "Kubernetes", [], None, "kubernetes"),
    ("JS framework", "React", [], None, "react"),
    ("JS framework", "Vue", [], None, "vue"),
    ("JS framework", "Angular", [], None, "ng-app"),
    ("JS framework", "Svelte", [], None, "svelte"),
    ("JS framework", "Ember", [], None, 'id="ember"'),
    ("JS framework", "Backbone", [], None, "backbone"),
    ("JS library", "jQuery", [], None, "jquery"),
    ("JS library", "lodash", [], None, "lodash"),
    ("JS library", "Bootstrap", [], None, "bootstrap"),
    ("JS library", "Tailwind CSS", [], None, "tailwind"),
    ("JS library", "Bulma", [], None, "bulma"),
    ("JS library", "Moment.js", [], None, "moment"),
    ("JS library", "Axios", [], None, "axios"),
    ("Webmail", "Roundcube", [], None, "roundcube"),
    ("Webmail", "SquirrelMail", [], None, "squirrelmail"),
    ("Forum", "phpBB", [], None, "phpbb"),
    ("Forum", "Discourse", [], None, "discourse"),
    ("CRM/CMS", "Salesforce", [], None, "salesforce"),
    ("CRM/CMS", "HubSpot", [], None, "hubspot"),
    ("CRM/CMS", "Drupal Commerce", [], None, "commerce"),
    ("Statically rendered", "Gatsby", [], None, 'meta name="generator" content="Gatsby'),
    ("Statically rendered", "Astro", [], None, 'meta name="generator" content="Astro'),
    ("Statically rendered", "Docusaurus", [], None, "docusaurus"),
]

# WAF / CDN detection signatures (header -> product).
WAF_SIGNATURES: list[tuple[str, str, str]] = [
    # (header_lower, needle, product)
    ("server", "cloudflare", "Cloudflare"),
    ("cf-ray", "", "Cloudflare"),
    ("server", "cloudfront", "AWS CloudFront"),
    ("x-amz-cf-id", "", "AWS CloudFront"),
    ("x-akamai-transformed", "", "Akamai"),
    ("x-akamai-request-id", "", "Akamai"),
    ("server", "akamaighost", "Akamai"),
    ("x-served-by", "cache-", "Fastly"),
    ("server", "imperva", "Imperva Incapsula"),
    ("x-iinfo", "", "Imperva Incapsula"),
    ("x-cdn", "incapsula", "Imperva Incapsula"),
    ("server", "sucuri", "Sucuri"),
    ("x-sucuri-id", "", "Sucuri"),
    ("x-sucuri-cache", "", "Sucuri"),
    ("server", "f5 big-ip", "F5 BIG-IP ASM"),
    ("x-waf-event-id", "", "AWS WAF"),
    ("x-amzn-waf", "", "AWS WAF"),
    ("server", "barracuda", "Barracuda"),
    ("server", "fortinet", "Fortinet FortiWeb"),
    ("server", "fortiweb", "Fortinet FortiWeb"),
    ("x-cdn", "sucuri", "Sucuri"),
    ("x-cdn", "stackpath", "StackPath"),
    ("server", "stackpath", "StackPath"),
    ("server", "ddos-guard", "DDoS-Guard"),
    ("server", "arvancloud", "ArvanCloud"),
    ("server", "qcdn", "Qrator"),
    ("server", "edgecast", "Verizon Edgecast"),
    ("server", "yundun", "Alibaba Cloud WAF"),
    ("x-yd-info", "", "Alibaba Cloud WAF"),
    ("server", "tengine", "Alibaba Tengine"),
    ("x-cache", "akamai", "Akamai"),
    ("server", "section.io", "section.io"),
    ("x-section-io-id", "", "section.io"),
]


# ---------------------------------------------------------------------------
# Favicon hashing (Shodan/Sn1per-style host fingerprinting)
# ---------------------------------------------------------------------------
#
# Shodan indexes every favicon it crawls under a 32-bit signed MurmurHash3
# of the file's base64 representation (``http.favicon.hash``), wrapped to
# standard line length 76 by ``base64.encodebytes``. A favicon hash is a
# cheap, very high-confidence pivot: default favicons for a given product
# (Jenkins, GitLab, a specific admin panel, a malware C2 panel, etc.) hash
# identically across every installation that never replaced the default
# icon, letting an operator search ``http.favicon.hash:<value>`` on Shodan /
# Censys to find every other exposed instance of the same software --
# exactly the kind of attack-surface pivot Sn1per's OSINT phase is built
# around. Implemented here as pure-Python MurmurHash3 (x86, 32-bit) so no
# ``mmh3`` C-extension dependency is required.


def _mmh3_32(data: bytes, seed: int = 0) -> int:
    """Pure-Python MurmurHash3 (x86, 32-bit), returned as a signed int.

    Matches the output of the ``mmh3.hash()`` C extension bit-for-bit, which
    is what Shodan/Censys use to compute ``http.favicon.hash``.
    """

    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded_end = length & ~3

    for i in range(0, rounded_end, 4):
        k1 = (data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24)) & 0xFFFFFFFF
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    k1 = 0
    tail = length & 3
    if tail == 3:
        k1 ^= data[rounded_end + 2] << 16
    if tail >= 2:
        k1 ^= data[rounded_end + 1] << 8
    if tail >= 1:
        k1 ^= data[rounded_end]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    # Shodan/mmh3 report the *signed* 32-bit value.
    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1


def favicon_hash(content: bytes) -> int | None:
    """Return the Shodan-style favicon hash for raw favicon bytes, or None."""
    if not content:
        return None
    b64 = base64.encodebytes(content)
    return _mmh3_32(b64)


# ---------------------------------------------------------------------------
# Active subdomain brute-force
# ---------------------------------------------------------------------------
#
# Complements the passive crt.sh (Certificate Transparency) lookup:
# subdomains that were never issued a logged TLS certificate (internal
# tools, staging hosts behind a wildcard cert, etc.) are invisible to CT-log
# recon but often resolve from a short, high-signal wordlist -- the same
# approach Sn1per/Sublist3r/AltDNS use. Kept intentionally small (~90
# entries) so a scan stays fast; the crawler/report still note that a larger
# external wordlist can be supplied for deeper coverage.
COMMON_SUBDOMAIN_WORDLIST: list[str] = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "autodiscover", "admin", "administrator", "api", "api-staging", "app",
    "apps", "staging", "stage", "dev", "develop", "development", "test",
    "testing", "qa", "uat", "demo", "beta", "preprod", "prod", "production",
    "internal", "intranet", "portal", "secure", "vpn", "remote", "gateway",
    "proxy", "cdn", "static", "assets", "img", "images", "media", "files",
    "download", "downloads", "upload", "uploads", "backup", "backups", "old",
    "new", "legacy", "archive", "db", "database", "mysql", "postgres",
    "redis", "mongo", "sql", "git", "gitlab", "github", "jenkins", "ci",
    "cd", "build", "jira", "confluence", "wiki", "docs", "documentation",
    "support", "helpdesk", "status", "monitor", "monitoring", "grafana",
    "kibana", "prometheus", "metrics", "logs", "logging", "sentry", "elk",
    "k8s", "kubernetes", "docker", "registry", "artifactory", "nexus",
    "sso", "auth", "login", "oauth", "idp", "identity", "accounts",
    "dashboard", "console", "panel", "cpanel", "whm", "webdisk", "ns3",
    "mx", "mx1", "mx2", "imap", "pop3", "ldap", "radius", "dns", "ns",
    "m", "mobile", "shop", "store", "checkout", "payment", "payments",
    "billing", "blog", "news", "forum", "community", "chat", "video",
    "stream", "stream1", "crm", "erp", "hr", "finance", "sandbox", "lab",
    "labs", "research", "office", "corp", "partners", "partner", "client",
    "clients", "customer", "customers", "edge", "origin", "cache", "lb",
    "loadbalancer", "firewall", "fw", "bastion", "jump",
]

# Dangling-CNAME subdomain-takeover fingerprints (Sn1per / can-i-take-over-
# xyz style). Each entry is (service-label, [cname-suffix-needles],
# [body-or-error needle proving the service responded but the name is
# unclaimed]). A hit means: the subdomain's CNAME still points at a
# third-party platform, but that platform has nothing registered for the
# name -- so anyone can claim it there and serve content under the
# organization's hostname.
SUBDOMAIN_TAKEOVER_FINGERPRINTS: list[tuple[str, list[str], list[str]]] = [
    ("GitHub Pages", ["github.io", "github.map.fastly.net"], ["there isn't a github pages site here"]),
    ("Heroku", ["herokuapp.com", "herokudns.com", "herokussl.com"], ["no such app", "heroku | no such app"]),
    ("AWS S3", ["s3.amazonaws.com", "s3-website"], ["nosuchbucket", "the specified bucket does not exist"]),
    ("Shopify", ["myshopify.com"], ["sorry, this shop is currently unavailable"]),
    ("Fastly", ["fastly.net"], ["fastly error: unknown domain"]),
    ("Pantheon", ["pantheonsite.io"], ["the gods are wise", "404 error unknown site"]),
    ("Unbounce", ["unbouncepages.com"], ["the requested url was not found on this server"]),
    ("Desk.com", ["desk.com"], ["please try again or try desk.com free for 14 days"]),
    ("Tumblr", ["domains.tumblr.com"], ["whatever you were looking for doesn't currently exist at this address"]),
    ("WordPress.com", ["wordpress.com"], ["do you want to register"]),
    ("Zendesk", ["zendesk.com"], ["help center closed"]),
    ("Surge.sh", ["surge.sh"], ["project not found"]),
    ("Cargo Collective", ["cargocollective.com"], ["404 not found"]),
    ("Statuspage", ["statuspage.io"], ["you are being", "statuspage.io"]),
    ("UserVoice", ["uservoice.com"], ["this uservoice subdomain is currently available"]),
    ("Ghost(Pro)", ["ghost.io"], ["the thing you were looking for is no longer here"]),
    ("Bitbucket", ["bitbucket.io"], ["repository not found"]),
    ("Netlify", ["netlify.app", "netlify.com"], ["not found - request id"]),
    ("Azure", ["azurewebsites.net", "cloudapp.net", "blob.core.windows.net", "trafficmanager.net"],
     ["404 web site not found"]),
    ("Readme.io", ["readme.io"], ["project doesnt exist... yet!"]),
    ("Campaign Monitor", ["createsend.com"], ["trying to access your account?"]),
    ("Helpjuice", ["helpjuice.com"], ["we could not find what you're looking for"]),
    ("Helpscout", ["helpscoutdocs.com"], ["no settings were found for this company"]),
    ("Strikingly", ["strikinglydns.com"], ["but the page you were looking for doesn't exist"]),
    ("Uptimerobot", ["stats.uptimerobot.com"], ["page not found"]),
    ("Vercel", ["vercel.app", "now.sh"], ["404: not_found", "deployment_not_found"]),
    ("Webflow", ["webflow.io", "proxy-ssl.webflow.com"], ["the page you are looking for doesn't exist"]),
]
