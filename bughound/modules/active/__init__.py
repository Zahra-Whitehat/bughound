"""Active scanner modules.

These modules send crafted payloads to discovered parameters to verify
exploitable vulnerabilities. They only run when the operator enables aggressive
mode (--aggressive) against an authorized target.
"""

from . import (  # noqa: F401
    advisory,
    command_injection,
    default_logins,
    graphql_hunter,
    header_injection,
    host_header_poison,
    jwt_attacks,
    nosqli,
    open_redirect,
    path_traversal,
    prototype_pollution,
    sqli,
    ssrf,
    xss,
    xxe_prober,
)
