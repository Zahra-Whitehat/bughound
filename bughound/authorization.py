"""Authorization gate.

bughound is a defensive / authorized-pentest tool. It refuses to scan a target
unless the operator has explicitly asserted they are authorized to test it. This
module centralizes that check so no scan can start without a recorded assertion
of scope.

It also supports a **denylist**: hosts or URL prefixes the operator marks as
forbidden. Denied targets are blocked outright and take precedence over the
allowlist -- the agent never crawls or sends a request to them.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from urllib.parse import urlparse

import yaml


class AuthorizationError(Exception):
    """Raised when a scan is attempted against an unauthorized target."""


def _norm_url(url: str) -> str:
    return (url or "").strip().rstrip("/").lower()


@dataclass
class Scope:
    """A record of what the operator is authorized to test.

    ``denied_hosts`` (glob patterns matched against the host) and
    ``denied_urls`` (URL prefixes) are always forbidden and override the
    allowlist.
    """

    allowed_hosts: list[str]
    denied_hosts: list[str] = field(default_factory=list)
    denied_urls: list[str] = field(default_factory=list)
    note: str = ""

    def permits(self, host: str) -> bool:
        host = host.lower()
        for pattern in self.allowed_hosts:
            if fnmatch.fnmatch(host, pattern.lower()):
                return True
        return False

    def host_denied(self, host: str) -> bool:
        host = host.lower()
        return any(fnmatch.fnmatch(host, p.lower()) for p in self.denied_hosts)

    def url_denied(self, url: str) -> bool:
        """True if ``url`` is on the denylist (denied host or denied URL prefix)."""

        if self.host_denied(host_of(url)):
            return True
        target = _norm_url(url)
        for prefix in self.denied_urls:
            if target == _norm_url(prefix) or target.startswith(_norm_url(prefix)):
                return True
        return False


def load_scope(
    scope_file: str | None = None,
    explicit_hosts: list[str] | None = None,
    denied_hosts: list[str] | None = None,
    denied_urls: list[str] | None = None,
    note: str = "",
) -> Scope:
    """Build the scope from a file, env, and/or explicit hosts/denylist."""

    hosts: list[str] = []
    dhosts: list[str] = []
    durls: list[str] = []
    if scope_file:
        with open(scope_file) as fh:
            data = yaml.safe_load(fh) or {}
        hosts.extend(data.get("allowed_hosts", []))
        dhosts.extend(data.get("denied_hosts", []))
        durls.extend(data.get("denied_urls", []))
        note = note or data.get("note", "")
    env_hosts = os.environ.get("BUGHOUND_AUTHORIZED_HOSTS", "")
    if env_hosts:
        hosts.extend(h.strip() for h in env_hosts.split(",") if h.strip())
    env_denied = os.environ.get("BUGHOUND_DENIED_HOSTS", "")
    if env_denied:
        dhosts.extend(h.strip() for h in env_denied.split(",") if h.strip())
    if explicit_hosts:
        hosts.extend(explicit_hosts)
    if denied_hosts:
        dhosts.extend(denied_hosts)
    if denied_urls:
        durls.extend(denied_urls)
    return Scope(
        allowed_hosts=[h for h in hosts if h],
        denied_hosts=[h for h in dhosts if h],
        denied_urls=[u for u in durls if u],
        note=note,
    )


def host_of(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return (parsed.hostname or "").lower()


def authorize(url: str, scope: Scope, confirmed: bool) -> str:
    """Return an authorization note or raise AuthorizationError.

    A target is authorized only if it is not on the denylist AND the host is
    inside the declared scope AND the operator has explicitly confirmed
    authorization (``confirmed``).
    """

    host = host_of(url)
    if not host:
        raise AuthorizationError(f"Could not parse a host from target: {url!r}")

    if scope.url_denied(url):
        raise AuthorizationError(
            f"Target {url!r} is on the denylist (forbidden / out of scope). "
            "It will not be scanned. Remove it from denied_hosts/denied_urls to allow."
        )
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
