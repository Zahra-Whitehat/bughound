"""A small same-origin crawler that discovers URLs and injectable parameters."""

from __future__ import annotations

import warnings
from collections.abc import Callable
from urllib.parse import parse_qsl, urljoin, urlparse

from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning

from .http_client import HttpClient
from .modules.base import RequestTarget

warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    # Normalize ports: treat None as default (80 for http, 443 for https)
    port_a = pa.port or (443 if pa.scheme == "https" else 80)
    port_b = pb.port or (443 if pb.scheme == "https" else 80)
    return (pa.scheme, pa.hostname, port_a) == (pb.scheme, pb.hostname, port_b)


def _sibling_platform_host(a: str, b: str) -> bool:
    """True when ``a`` is a sibling host of ``b`` under the same registrable
    domain (last two labels), OR the same hostname on a different port
    (local mock/labs). Records platform infrastructure like the Academy
    exploit server without ever crawling across to unrelated websites."""
    pa, pb = urlparse(a), urlparse(b)
    ha, hb = (pa.hostname or ""), (pb.hostname or "")
    if not ha or not hb:
        return False
    if ha == hb:
        return True  # same hostname (any port)
    la, lb = ha.rsplit(".", 2)[-2:], hb.rsplit(".", 2)[-2:]
    return bool(la) and la == lb


async def crawl(
    client: HttpClient,
    base_url: str,
    max_urls: int = 40,
    max_depth: int = 2,
    is_denied: Callable[[str], bool] | None = None,
    log: Callable[[str], None] | None = None,
) -> tuple[list[str], list[RequestTarget], str, dict[str, str]]:
    """Breadth-first same-origin crawl.

    ``is_denied(url)`` marks forbidden destinations: they are never requested,
    never enqueued, and never recorded as injectable targets.

    ``log(msg)`` is an optional progress callback. When supplied, the crawler
    emits a human-readable line for every fetch failure (timeout, TLS error,
    HTTP 4xx/5xx, denied-target block). Without it, failures are silent --
    which is the old behaviour and the reason scans sometimes returned
    "0 URLs" with no explanation.

    Returns (visited urls, request targets, seed_html, seed_headers).
    """

    denied = is_denied or (lambda _u: False)
    emit = log or (lambda _msg: None)
    seen: set[str] = set()
    visited: list[str] = []
    targets: list[RequestTarget] = []
    target_keys: set[str] = set()
    queue: list[tuple[str, int]] = [(base_url, 0)]
    seed_html = ""
    seed_headers: dict[str, str] = {}

    def add_target(rt: RequestTarget) -> None:
        key = f"{rt.method}:{rt.url}:{','.join(sorted(rt.params))}"
        if (rt.params or rt.source == "cookie") and key not in target_keys:
            target_keys.add(key)
            targets.append(rt)

    while queue and len(visited) < max_urls:
        url, depth = queue.pop(0)
        if url in seen or denied(url):
            continue
        seen.add(url)
        resp = await client.get(url)
        if not resp.ok:
            # Surface the failure reason so the operator can act on it.
            # The three common cases are: (a) timeout -- the target is slow
            # or asleep (PortSwigger labs, AWS Lambda cold starts); (b) TLS
            # error -- self-signed or expired cert; (c) 4xx/5xx -- the path
            # is gone or the host is blocking the UA. Without this log line
            # the user just sees "Discovered 0 URLs" with no clue why.
            if resp.error:
                emit(f"  fetch failed: {url} -> {resp.error}")
            elif resp.status:
                emit(f"  fetch returned HTTP {resp.status}: {url}")
            continue
        visited.append(resp.url)
        if not seed_html:
            seed_html, seed_headers = resp.text, resp.headers

        # Query params on this URL are injectable.
        qs = dict(parse_qsl(urlparse(url).query))
        if qs:
            add_target(RequestTarget(url=url.split("?")[0], method="GET", params=qs, source="query"))
        elif resp.headers.get("set-cookie"):
            # A page that issues cookies is a cookie *consumer* candidate
            # (session lookups, TrackingId-style analytics) -- record it so
            # cookie-parameter injection can be tested and re-targeted even
            # when it takes no query/form parameters at all.
            add_target(RequestTarget(url=url.split("?")[0], method="GET", params={}, source="cookie"))

        content_type = resp.headers.get("content-type", "")
        if "html" not in content_type:
            continue
        soup = BeautifulSoup(resp.text, "html.parser")

        # Forms -> request targets.
        for form in soup.find_all("form"):
            action = urljoin(resp.url, form.get("action") or resp.url)
            method = (form.get("method") or "get").upper()
            params: dict[str, str] = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    params[name] = inp.get("value") or "test"
            if _same_origin(action, base_url) and not denied(action):
                add_target(RequestTarget(url=action, method=method, params=params, source="form"))

        if depth >= max_depth:
            continue
        # Anchor links (primary discovery).
        for a in soup.find_all("a", href=True):
            link = urljoin(resp.url, a["href"]).split("#")[0]
            if _same_origin(link, base_url) and link not in seen and not denied(link):
                queue.append((link, depth + 1))
                lqs = dict(parse_qsl(urlparse(link).query))
                if lqs:
                    add_target(
                        RequestTarget(url=link.split("?")[0], method="GET", params=lqs, source="query")
                    )
            elif (
                link not in seen
                and not denied(link)
                and _sibling_platform_host(link, base_url)
            ):
                # Sibling host of the SAME platform (same registrable domain,
                # e.g. the Academy's exploit-<id> server): record it so the
                # solve phase can discover platform infrastructure, but do
                # NOT recurse -- the crawler stays same-origin by design.
                seen.add(link)
                visited.append(link)
        # <link href> (stylesheets, icons, preconnect, manifest) -- record
        # them in the visited list so the recon modules see them, but don't
        # recurse (they aren't HTML).
        for link_tag in soup.find_all("link", href=True):
            link = urljoin(resp.url, link_tag["href"]).split("#")[0]
            if _same_origin(link, base_url) and link not in seen and not denied(link):
                seen.add(link)
                visited.append(link)
        # <script src> and <iframe src> -- same-origin scripts are worth
        # fetching once so the JS-endpoints / sourcemap modules can scan them
        # without each doing their own fetch.
        for tag in soup.find_all(["script", "iframe"], src=True):
            link = urljoin(resp.url, tag["src"]).split("#")[0]
            if _same_origin(link, base_url) and link not in seen and not denied(link):
                seen.add(link)
                visited.append(link)

    return visited, targets, seed_html, seed_headers
