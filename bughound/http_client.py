"""Thin async HTTP client wrapper used by scanner modules."""

from __future__ import annotations

import time
from collections.abc import Callable
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

    @property
    def ok(self) -> bool:
        return self.error is None


class HttpClient:
    """Async HTTP client with sane defaults for scanning."""

    def __init__(
        self,
        timeout: float = 15.0,
        user_agent: str = "bughound/0.1",
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
        except Exception as exc:  # noqa: BLE001 - surface network errors to modules
            return Response(
                url=url,
                status=0,
                headers={},
                text="",
                elapsed=time.monotonic() - start,
                request_method=method,
                error=f"{type(exc).__name__}: {exc}",
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

    async def aclose(self) -> None:
        await self._client.aclose()
