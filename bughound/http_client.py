"""Thin async HTTP client wrapper used by scanner modules."""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx


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
    ) -> None:
        headers = {"User-Agent": user_agent}
        if extra_headers:
            headers.update(extra_headers)
        self._client = httpx.AsyncClient(
            timeout=timeout,
            headers=headers,
            follow_redirects=follow_redirects,
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
        try:
            kwargs = dict(headers=headers, data=data, json=json, params=params)
            if follow_redirects is not None:
                kwargs["follow_redirects"] = follow_redirects
            resp = await self._client.request(method, url, **kwargs)
            return Response(
                url=str(resp.url),
                status=resp.status_code,
                headers={k.lower(): v for k, v in resp.headers.items()},
                text=resp.text,
                elapsed=time.monotonic() - start,
                request_method=method,
                request_headers=dict(resp.request.headers),
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

    async def get(self, url: str, **kwargs) -> Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> Response:
        return await self.request("POST", url, **kwargs)

    async def aclose(self) -> None:
        await self._client.aclose()
