"""Authorization gate.

bughound is a defensive / authorized-pentest tool. It refuses to scan a target
unless the operator has explicitly asserted they are authorized to test it. This
module centralizes that check so no scan can start without a recorded assertion
of scope.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass
from urllib.parse import urlparse

import yaml


class AuthorizationError(Exception):
    """Raised when a scan is attempted against an unauthorized target."""


@dataclass
class Scope:
    """A record of what the operator is authorized to test."""

    allowed_hosts: list[str]
    note: str = ""

    def permits(self, host: str) -> bool:
        host = host.lower()
        for pattern in self.allowed_hosts:
            if fnmatch.fnmatch(host, pattern.lower()):
                return True
        return False


def load_scope(
    scope_file: str | None = None,
    explicit_hosts: list[str] | None = None,
    note: str = "",
) -> Scope:
    """Build the authorized scope from a file, env, and/or explicit hosts."""

    hosts: list[str] = []
    if scope_file:
        with open(scope_file) as fh:
            data = yaml.safe_load(fh) or {}
        hosts.extend(data.get("allowed_hosts", []))
        note = note or data.get("note", "")
    env_hosts = os.environ.get("BUGHOUND_AUTHORIZED_HOSTS", "")
    if env_hosts:
        hosts.extend(h.strip() for h in env_hosts.split(",") if h.strip())
    if explicit_hosts:
        hosts.extend(explicit_hosts)
    return Scope(allowed_hosts=[h for h in hosts if h], note=note)


def host_of(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return (parsed.hostname or "").lower()


def authorize(url: str, scope: Scope, confirmed: bool) -> str:
    """Return an authorization note or raise AuthorizationError.

    A target is authorized only if the host is inside the declared scope AND the
    operator has explicitly confirmed authorization (``confirmed``). This is a
    deliberate speed bump against pointing the tool at systems you do not own or
    have permission to test.
    """

    host = host_of(url)
    if not host:
        raise AuthorizationError(f"Could not parse a host from target: {url!r}")

    if not scope.permits(host):
        raise AuthorizationError(
            f"Host {host!r} is not in the authorized scope. "
            "Add it via --scope file, --authorize-host, or BUGHOUND_AUTHORIZED_HOSTS. "
            "Only scan systems you own or are explicitly permitted to test."
        )
    if not confirmed:
        raise AuthorizationError(
            f"Host {host!r} is in scope, but you must explicitly confirm authorization "
            "(pass --i-am-authorized on the CLI, or authorized=true to the API)."
        )
    return f"Authorized: host {host} in declared scope. {scope.note}".strip()
