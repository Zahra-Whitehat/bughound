"""Active scanner modules.

These modules send crafted payloads to discovered parameters to verify
exploitable vulnerabilities. They only run when the operator enables aggressive
mode (--aggressive) against an authorized target.
"""

from . import (  # noqa: F401
    advisory,
    command_injection,
    header_injection,
    nosqli,
    open_redirect,
    path_traversal,
    sqli,
    ssrf,
    xss,
)
