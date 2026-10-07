"""Thin async HTTP client wrapper used by scanner modules."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass

import httpx


class DeniedTargetError(Exception):
    """Raised internally when a request targets a denylisted destination."""


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str]
    text: str
    elapsed: float
    request_method: str = "GET"
    request_headers: dict[str, str] | None = None
    error: str | None = None
    #: Raw response bytes, undecoded. Needed by any check that must hash or
    #: inspect binary content as-is (favicon hashing, file-signature checks)
    #: rather than through ``text``'s charset-decoded (and therefore lossy
    #: for binary payloads) view.
    content: bytes = b""

    @property
    def ok(self) -> bool:
        return self.error is None


class HttpClient:
    """Async HTTP client with sane defaults for scanning."""

    def __init__(
        self,
        timeout: float = 30.0,
        user_agent: str = (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        extra_headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
        verify_tls: bool = False,
        blocked: Callable[[str], bool] | None = None,
    ) -> None:
        # ``blocked(url) -> bool`` is the denylist guard: any request to a URL it
        # returns True for is refused before a connection is opened, so the agent
        # never touches forbidden / out-of-scope targets.
        self._blocked = blocked
        self.blocked_requests: list[str] = []
        self._default_follow = follow_redirects
        headers = {"User-Agent": user_agent}
        if extra_headers:
            headers.update(extra_headers)
        # When a denylist guard is active we never let httpx auto-follow
        # redirects: each hop is inspected manually so a redirect can't lead the
        # scanner into a forbidden destination.
        self._client = httpx.AsyncClient(
            timeout=timeout,
            headers=headers,
            follow_redirects=False if blocked else follow_redirects,
            verify=verify_tls,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        data=None,
        json=None,
        params=None,
        follow_redirects: bool | None = None,
    ) -> Response:
        start = time.monotonic()
        if self._blocked and self._blocked(url):
            self.blocked_requests.append(url)
            return Response(
                url=url,
                status=0,
                headers={},
                text="",
                elapsed=0.0,
                request_method=method,
                error=f"DeniedTargetError: {url} is on the denylist (request blocked)",
            )
        want_follow = self._default_follow if follow_redirects is None else follow_redirects
        # Servers frequently close a keep-alive connection after an error
        # response (e.g. the 500 an SQLi probe triggered). If the next request
        # reuses that stale connection it fails with ReadError/RemoteProtocol-
        # Error even though the target is fine -- so transient transport
        # errors are retried once on a fresh connection before being reported.
        last_exc: Exception | None = None
        for attempt in range(2):
            try:
                kwargs = dict(headers=headers, data=data, json=json, params=params)
                if self._blocked is None:
                    if follow_redirects is not None:
                        kwargs["follow_redirects"] = follow_redirects
                    resp = await self._client.request(method, url, **kwargs)
                else:
                    resp = await self._request_guarded(method, url, want_follow, kwargs)
                return Response(
                    url=str(resp.url),
                    status=resp.status_code,
                    headers={k.lower(): v for k, v in resp.headers.items()},
                    text=resp.text,
                    elapsed=time.monotonic() - start,
                    request_method=method,
                    request_headers=dict(resp.request.headers),
                    content=resp.content,
                )
            except DeniedTargetError as exc:
                self.blocked_requests.append(str(exc))
                return Response(
                    url=url,
                    status=0,
                    headers={},
                    text="",
                    elapsed=time.monotonic() - start,
                    request_method=method,
                    error=f"DeniedTargetError: redirect to {exc} blocked (denylist)",
                )
            except (httpx.ReadError, httpx.RemoteProtocolError, httpx.ConnectError) as exc:
                last_exc = exc
                if attempt == 0:
                    await asyncio.sleep(0.15)
                    continue
            except Exception as exc:  # noqa: BLE001 - surface network errors to modules
                last_exc = exc
                break
        return Response(
            url=url,
            status=0,
            headers={},
            text="",
            elapsed=time.monotonic() - start,
            request_method=method,
            error=f"{type(last_exc).__name__}: {last_exc}" if last_exc else "request failed",
        )

    async def _request_guarded(
        self, method: str, url: str, follow: bool, kwargs: dict
    ) -> httpx.Response:
        """Issue a request, manually following redirects and refusing any hop
        whose destination is on the denylist."""

        resp = await self._client.request(method, url, **kwargs)
        if not follow:
            return resp
        redirects = 0
        while resp.is_redirect and redirects < 20:
            location = resp.headers.get("location")
            if not location:
                break
            next_url = str(resp.next_request.url) if resp.next_request else location
            if self._blocked and self._blocked(next_url):
                raise DeniedTargetError(next_url)
            redirects += 1
            request = resp.next_request
            if request is None:
                break
            resp = await self._client.send(request)
        return resp

    async def get(self, url: str, **kwargs) -> Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> Response:
        return await self.request("POST", url, **kwargs)

    def jar_cookies(self) -> dict[str, str]:
        """Snapshot of the session cookie jar (name -> value).

        Used by injection modules to test cookie parameters (cookies are
        request inputs just like query/form parameters).
        """
        return {c.name: c.value for c in self._client.cookies.jar}

    @contextmanager
    def cookie_override(self, name: str, value: str) -> Iterator[None]:
        """Temporarily replace cookie ``name`` in the session jar.

        Cookie-parameter injection (TrackingId-style labs) needs the request
        to carry a *different* cookie value while everything else -- session,
        other cookies -- stays identical. The previous value is restored on
        exit, so the scanner's own session state is never polluted. Safe for
        the sequential (single-event-loop) way modules issue requests.
        """
        jar = self._client.cookies
        saved = [c for c in list(jar.jar) if c.name == name]
        for c in saved:
            jar.jar.clear(c.domain, c.path, c.name)
        jar.set(name, value)
        try:
            yield
        finally:
            for c in list(jar.jar):
                if c.name == name:
                    jar.jar.clear(c.domain, c.path, c.name)
            for c in saved:
                jar.jar.set_cookie(c)

    async def aclose(self) -> None:
        await self._client.aclose()
