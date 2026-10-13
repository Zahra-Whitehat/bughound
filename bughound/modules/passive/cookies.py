"""Cookie security-flag checks."""

from __future__ import annotations

from http.cookies import SimpleCookie

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register


@register
class CookiesModule(Module):
    name = "cookies"
    categories = [Category.SESSION]
    passive = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen_cookies: set[str] = set()
        urls = [ctx.base_url] + [u for u in ctx.urls if u != ctx.base_url]
        for url in urls[:15]:
            resp = await ctx.client.get(url, follow_redirects=False)
            if not resp.ok:
                continue
            set_cookie = resp.headers.get("set-cookie")
            if not set_cookie:
                continue
            self._inspect(resp.url, set_cookie, seen_cookies, findings)
        return findings

    def _inspect(self, url, set_cookie, seen_cookies, findings) -> None:
        cookie = SimpleCookie()
        cookie.load(set_cookie)
        for name, morsel in cookie.items():
            if name in seen_cookies:
                continue
            seen_cookies.add(name)
            issues = []
            if not morsel["secure"]:
                issues.append("missing Secure")
            if not morsel["httponly"]:
                issues.append("missing HttpOnly")
            if not morsel["samesite"]:
                issues.append("missing SameSite")
            if issues:
                sensitive = any(k in name.lower() for k in ("sess", "auth", "token", "sid", "jwt"))
                sev = Severity.MEDIUM if sensitive else Severity.LOW
                findings.append(
                    Finding(
                        category=Category.SESSION,
                        title=f"Cookie '{name}' missing security flags",
                        severity=sev,
                        confidence="firm",
                        url=url,
                        description=(
                            f"Cookie '{name}' is set without: {', '.join(issues)}. "
                            "This weakens protection against theft (XSS) and CSRF."
                        ),
                        evidence=f"Set-Cookie: {name}=...; {'; '.join(issues)}",
                        remediation="Set Secure, HttpOnly and SameSite=Lax/Strict on session cookies.",
                        cwe="CWE-614",
                        module=self.name,
                        verified=True,
                    )
                )
