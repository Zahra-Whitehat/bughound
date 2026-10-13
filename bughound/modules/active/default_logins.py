"""Default-credential checks -- the credential-tester persona, tightly gated.

This is bughound's analogue of Sn1per's ``-b`` bruteforce switch, with
guardrails that make it compatible with an authorized-testing tool:

- **Never on by default.** The module runs only when the operator passes
  ``--brute`` or selects nuke mode (``config.bruteforce``).
- **A handful of pairs, once.** Four well-known default pairs per login
  form, at most two forms per scan. Each pair goes through the same
  failed-login-baseline differential the SQLi takeover proof uses, so a
  success is a *verified* authentication bypass, not a guess.
- **No lockout risk by design.** 8 requests to one endpoint cannot
  lock an account; a warning is printed in the finding's evidence so
  triagers know what was sent.

Success detection reuses ``bughound.exploits.auth.attempt_login`` --
identical semantics to the exploit phase (auth markers, fresh session
cookie, status/redirect differential vs a wrong-password baseline).
"""

from __future__ import annotations

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register

#: Ordered by likelihood; deliberately tiny (4 pairs x 2 forms = <=16 requests).
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("administrator", "admin123"),
    ("root", "root"),
]

MAX_LOGIN_FORMS = 2


@register
class DefaultLoginsModule(Module):
    name = "default-logins"
    categories = [Category.BRUTE_FORCE]
    passive = False
    aggressive_required = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        if not ctx.config.bruteforce:
            return findings  # strictly opt-in (Sn1per -b style)

        # Imported lazily: the exploits package pulls in the whole active-module
        # registry via evidence.py -> modules.active, so a top-level import here
        # would create a circular import at package-initialization time.
        from ...exploits.auth import attempt_login, best_login_target

        seen_urls: set[str] = set()
        attempts = 0
        while attempts < MAX_LOGIN_FORMS:
            target = best_login_target(ctx)
            if target is None or target.url in seen_urls:
                break
            seen_urls.add(target.url)
            attempts += 1
            for username, password in DEFAULT_CREDENTIALS:
                login = await attempt_login(ctx, target, username, password)
                if login.success:
                    findings.append(
                        Finding(
                            category=Category.BRUTE_FORCE,
                            title=f"Default credentials accepted: {username}:{password}",
                            severity=Severity.HIGH,
                            confidence="confirmed",
                            url=target.url,
                            description=(
                                f"The login endpoint at {target.url} authenticates the default "
                                f"pair {username}:{password}. This module is strictly opt-in "
                                "(--brute/nuke mode); only 4 well-known default pairs were tried "
                                "against 1 form, each validated against a failed-login baseline."
                            ),
                            evidence=(
                                f"login with {username}:{password} succeeded; failed-credential "
                                f"baseline comparison: {login.detail}\n"
                                "(requests sent to this endpoint: 2 per pair; no lockout risk)"
                            ),
                            request=f"{target.method.upper()} {target.url} ({username}/{password})",
                            response_excerpt=login.raw_response[:600] if login.raw_response else "",
                            remediation=(
                                "Remove/change all default credentials before deployment; add "
                                "credential-stuffing detection and rate limiting."
                            ),
                            cwe="CWE-798",
                            module=self.name,
                            verified=True,
                        )
                    )
                    break  # one success per form is enough
        return findings
