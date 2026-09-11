"""Passive (non-intrusive) scanner modules.

These modules never send attack payloads; they inspect responses, headers,
cookies, TLS and well-known paths. They are safe to run against any target the
operator is authorized to test.
"""

from . import (  # noqa: F401
    cookies,
    cors,
    info_disclosure,
    secrets,
    security_headers,
    tls,
)
