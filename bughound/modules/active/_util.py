"""Shared helpers for active (payload-sending) modules."""

from __future__ import annotations

from dataclasses import replace

from ...http_client import HttpClient, Response
from ..base import RequestTarget

COOKIE_PREFIX = "cookie:"

# Marker inside ``RequestTarget.body_template`` where the payload goes.
INJ_PLACEHOLDER = "{INJ}"


def is_cookie_param(param: str) -> bool:
    """True when ``param`` names a cookie (``cookie:TrackingId``)."""
    return param.startswith(COOKIE_PREFIX)


def cookie_name(param: str) -> str:
    return param[len(COOKIE_PREFIX):]


def xml_entity_encode(value: str) -> str:
    """Numeric-character-reference encode ``value`` (``A`` -> ``&#65;``).

    WAF-bypass primitive for XML endpoints: the filter inspects the *raw*
    body for SQL keywords, but the XML parser decodes character references
    before the value reaches the SQL engine -- so an entity-encoded payload
    carries no keywords for the filter to match while the backend still
    executes the original injection.
    """
    return "".join(f"&#{ord(c)};" for c in value)


def encode_payload(rt: RequestTarget, value: str) -> str:
    """Apply the target's configured payload encoding (if any)."""
    if (rt.encoding or "") == "xml-entities":
        return xml_entity_encode(value)
    return value


def render_body(rt: RequestTarget, param: str, value: str) -> str:
    """Fill ``rt.body_template`` with the (encoded) payload.

    The template's ``{INJ}`` marker is THE injection point -- every exploit
    strategy re-targets it regardless of the logical ``param`` name. A
    template without the marker is sent verbatim (useful for a pure
    baseline). The value is encoded per ``rt.encoding`` *after* substitution
    position is chosen, so wrappers like ``' UNION SELECT ...--`` are
    encoded together with the base value.
    """
    body = rt.body_template
    if INJ_PLACEHOLDER in body:
        return body.replace(INJ_PLACEHOLDER, encode_payload(rt, value))
    # Fall back to a named placeholder matching the parameter.
    marker = "{" + param + "}"
    if marker in body:
        return body.replace(marker, encode_payload(rt, value))
    return body


async def _send_body(client: HttpClient, rt: RequestTarget, body: str) -> Response:
    headers = {"Content-Type": rt.content_type} if rt.content_type else None
    return await client.request(rt.method.upper() or "POST", rt.url, data=body, headers=headers)


async def send_with_param(
    client: HttpClient, rt: RequestTarget, param: str, value: str
) -> Response:
    """Send ``rt`` with ``param`` replaced by ``value``.

    ``param`` may be a query/form parameter, or a cookie reference of the
    form ``cookie:<name>`` -- in which case the request is sent with that
    cookie overridden (other cookies and session state are preserved and
    restored afterwards).

    Raw-body targets (``rt.body_template`` set, e.g. XML endpoints) ignore
    the parameter name and substitute the payload at the template's
    ``{INJ}`` marker instead.
    """
    if rt.body_template:
        if is_cookie_param(param):
            with client.cookie_override(cookie_name(param), value):
                return await _send_body(client, rt, render_body(rt, param, rt.params.get("INJ", "")))
        return await _send_body(client, rt, render_body(rt, param, value))

    if is_cookie_param(param):
        with client.cookie_override(cookie_name(param), value):
            if rt.method.upper() == "POST":
                return await client.post(rt.url, data=rt.params)
            return await client.get(rt.url, params=rt.params)

    params = dict(rt.params)
    params[param] = value
    if rt.method.upper() == "POST":
        return await client.post(rt.url, data=params)
    return await client.get(rt.url, params=params)


def clone_target(rt: RequestTarget) -> RequestTarget:
    return replace(rt, params=dict(rt.params))


def param_base_value(client: HttpClient, rt: RequestTarget, param: str) -> str:
    """Original (unmodified) value of a query/form/cookie parameter.

    Cookie parameters have no entry in ``rt.params`` -- their baseline value
    lives in the session jar. Raw-body targets carry the baseline value at
    the ``INJ`` key of ``rt.params``.
    """
    if is_cookie_param(param):
        return client.jar_cookies().get(cookie_name(param), "")
    if rt.body_template:
        return rt.params.get("INJ", "")
    return rt.params.get(param, "")


async def baseline(client: HttpClient, rt: RequestTarget) -> Response:
    if rt.body_template:
        return await _send_body(client, rt, render_body(rt, "INJ", rt.params.get("INJ", "")))
    if rt.method.upper() == "POST":
        return await client.post(rt.url, data=rt.params)
    return await client.get(rt.url, params=rt.params)
