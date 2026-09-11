"""Shared helpers for active (payload-sending) modules."""

from __future__ import annotations

from dataclasses import replace

from ...http_client import HttpClient, Response
from ..base import RequestTarget


async def send_with_param(
    client: HttpClient, rt: RequestTarget, param: str, value: str
) -> Response:
    """Send ``rt`` with ``param`` replaced by ``value``."""

    params = dict(rt.params)
    params[param] = value
    if rt.method.upper() == "POST":
        return await client.post(rt.url, data=params)
    return await client.get(rt.url, params=params)


def clone_target(rt: RequestTarget) -> RequestTarget:
    return replace(rt, params=dict(rt.params))


async def baseline(client: HttpClient, rt: RequestTarget) -> Response:
    if rt.method.upper() == "POST":
        return await client.post(rt.url, data=rt.params)
    return await client.get(rt.url, params=rt.params)
