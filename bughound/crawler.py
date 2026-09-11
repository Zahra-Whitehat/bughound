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
    return (pa.scheme, pa.hostname, pa.port) == (pb.scheme, pb.hostname, pb.port)


async def crawl(
    client: HttpClient,
    base_url: str,
    max_urls: int = 40,
    max_depth: int = 2,
    is_denied: Callable[[str], bool] | None = None,
) -> tuple[list[str], list[RequestTarget], str, dict[str, str]]:
    """Breadth-first same-origin crawl.

    ``is_denied(url)`` marks forbidden destinations: they are never requested,
    never enqueued, and never recorded as injectable targets.

    Returns (visited urls, request targets, seed_html, seed_headers).
    """

    denied = is_denied or (lambda _u: False)
    seen: set[str] = set()
    visited: list[str] = []
    targets: list[RequestTarget] = []
    target_keys: set[str] = set()
    queue: list[tuple[str, int]] = [(base_url, 0)]
    seed_html = ""
    seed_headers: dict[str, str] = {}

    def add_target(rt: RequestTarget) -> None:
        key = f"{rt.method}:{rt.url}:{','.join(sorted(rt.params))}"
        if rt.params and key not in target_keys:
            target_keys.add(key)
            targets.append(rt)

    while queue and len(visited) < max_urls:
        url, depth = queue.pop(0)
        if url in seen or denied(url):
            continue
        seen.add(url)
        resp = await client.get(url)
        if not resp.ok:
            continue
        visited.append(resp.url)
        if not seed_html:
            seed_html, seed_headers = resp.text, resp.headers

        # Query params on this URL are injectable.
        qs = dict(parse_qsl(urlparse(url).query))
        if qs:
            add_target(RequestTarget(url=url.split("?")[0], method="GET", params=qs, source="query"))

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
        for a in soup.find_all("a", href=True):
            link = urljoin(resp.url, a["href"]).split("#")[0]
            if _same_origin(link, base_url) and link not in seen and not denied(link):
                queue.append((link, depth + 1))
                lqs = dict(parse_qsl(urlparse(link).query))
                if lqs:
                    add_target(
                        RequestTarget(url=link.split("?")[0], method="GET", params=lqs, source="query")
                    )

    return visited, targets, seed_html, seed_headers
