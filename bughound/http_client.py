"""Thin async HTTP client wrapper used by scanner modules."""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass

import httpx

# Status codes that mean "the target is rate-limiting / overloaded". The
# Academy (and many hosting platforms) answer aggressive automated traffic
# with these instead of blocking outright. The client treats them as a
# global back-pressure signal: it opens an adaptive cooldown during which
# every subsequent request waits, and idempotent GETs are retried once.
THROTTLE_STATUSES = {429, 503, 504}


class DeniedTargetError(Exception):
    """Raised internally when a request targets a denylisted destination."""


# --- dead-lab signature (1.1.0) -------------------------------------------
# The PortSwigger academy gateway keeps answering while the lab BACKEND is
# gone: it returns HTTP 502/504 with a body of exactly this shape:
#   "Server Error: Gateway Timeout (0) connecting to <lab-host>"
# That body is the ONLY reliable way to tell "instance expired/stopped"
# apart from the SAME 504 status the academy also uses for back-pressure
# (throttling). Status alone is ambiguous; the body is definitive.
LAB_DEATH_RE = re.compile(
    r"Gateway\s+Timeout\s*\(\d+\)\s+connecting\s+to|Bad\s+Gateway\s*\(\d+\)\s+connecting\s+to",
    re.IGNORECASE,
)


def lab_dead_response(resp: Response) -> bool:
    """True when ``resp`` is the academy gateway's 'cannot reach the lab
    backend' error -- i.e. the lab instance is stopped or expired."""
    if resp.error or resp.status not in (500, 502, 503, 504):
        return False
    return bool(LAB_DEATH_RE.search(resp.text or ""))


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

    @property
    def status_ok(self) -> bool:
        """True when a response actually arrived AND its status is a success
        or redirect. ``ok`` only means "no transport error" -- a 504 gateway
        error page is ``ok`` but never ``status_ok``."""
        return self.error is None and 200 <= self.status < 400


class HttpClient:
    """Async HTTP client with sane defaults for scanning."""

    def __init__(
        self,
        timeout: float = 30.0,
        *,
        polite: bool = True,
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
        # --- Adaptive throttle handling (0.9.0) ---------------------------
        # ``polite`` enables the adaptive back-pressure gate below. The
        # counter/cooldown state is shared across the whole scan: modules,
        # crawler, exploit phase and solve phase all funnel through the same
        # ``request()`` method, so one overloaded target slows EVERYONE down
        # instead of every phase hammering the throttled host on its own.
        self.polite = polite
        self.throttle_events = 0
        self._cooldown_until = 0.0
        self.request_count = 0
        self.last_throttle_reason: str = ""
        # --- dead-lab tracking (1.1.0) ------------------------------------
        # Counts responses whose body matches the academy gateway's
        # "cannot connect to the lab backend" signature. The engine checks
        # this counter between phases: past a small threshold the scan is
        # aborted loudly instead of grinding a dead instance for minutes.
        self.lab_death_events = 0
        self.lab_death_urls: list[str] = []
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
        if self.polite:
            await self._throttle_wait()
        self.request_count += 1
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
                response = Response(
                    url=str(resp.url),
                    status=resp.status_code,
                    headers={k.lower(): v for k, v in resp.headers.items()},
                    text=resp.text,
                    elapsed=time.monotonic() - start,
                    request_method=method,
                    request_headers=dict(resp.request.headers),
                    content=resp.content,
                )
                if lab_dead_response(response):
                    # DEAD-LAB signature: the gateway says the backend is
                    # unreachable. This is NOT back-pressure -- sleeping and
                    # retrying would only slow the scan down, so record the
                    # event and return immediately without a throttle/retry.
                    self.lab_death_events += 1
                    self.lab_death_urls.append(url)
                    return response
                if resp.status_code in THROTTLE_STATUSES:
                    # Back-pressure: open a cooldown. GETs are idempotent, so
                    # one retry after the cooldown is safe and usually enough
                    # (the Academy throttle is burst-shaped, not permanent).
                    self._register_throttle(resp.status_code, url)
                    if attempt == 0 and method.upper() == "GET":
                        await asyncio.sleep(min(self._cooldown_remaining() + 0.5, 35.0))
                        continue
                return response
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

    # --- adaptive throttle gate -------------------------------------------

    def _register_throttle(self, status: int, url: str) -> None:
        """Record a throttling answer and open a progressive cooldown."""
        self.throttle_events += 1
        self.last_throttle_reason = f"HTTP {status} on {url}"
        # 2, 4, 8, 16, 30, 30 ... seconds -- gentle ramp, hard cap.
        cooldown = min(2.0 ** min(self.throttle_events, 5), 30.0)
        self._cooldown_until = max(self._cooldown_until, time.monotonic() + cooldown)

    def _cooldown_remaining(self) -> float:
        return max(0.0, self._cooldown_until - time.monotonic())

    async def _throttle_wait(self) -> None:
        """Sleep until the global cooldown expires (capped per request)."""
        remaining = self._cooldown_remaining()
        if remaining > 0:
            await asyncio.sleep(min(remaining, 35.0))

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

    def set_cookie(self, name: str, value: str) -> None:
        """Persistently set/replace cookie ``name`` in the session jar.

        Unlike :meth:`cookie_override` this keeps the new value after the
        call -- used by the solve phase once a privilege flip or stolen
        session has been PROVEN, so every subsequent action request in the
        same chain carries it. Solve-phase only; the scanner's detection
        modules never mutate session state.
        """
        jar = self._client.cookies
        for c in [c for c in list(jar.jar) if c.name == name]:
            jar.jar.clear(c.domain, c.path, c.name)
        jar.set(name, value)

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
