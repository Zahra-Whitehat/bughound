"""HTTP method enumeration via OPTIONS.

Sends a single ``OPTIONS`` request to the target root and parses the
``Allow`` / ``Accept-Patch`` / ``Accept-Post`` / ``Public`` headers to discover
which HTTP verbs the server accepts. Dangerous methods (``PUT``, ``DELETE``,
``TRACE``, ``CONNECT``, ``MOVE``, ``COPY``, ``LOCK``, ``UNLOCK``,
``PROPFIND``, ``MKCOL``) are flagged because they enable file upload/delete,
cross-site tracing, and WebDAV abuse.

Also issues a benign ``TRACE`` request and checks whether the response echoes
the request body back (Cross-Site Tracing, XST). The trace echo check is
defensive-only and never injects payloads -- if the server reflects the
trace, that's a finding.
"""

from __future__ import annotations

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register

# Methods that, when enabled, materially expand the attack surface.
RISKY_METHODS = {
    "PUT": "arbitrary file upload (web shell)",
    "DELETE": "arbitrary file deletion",
    "MOVE": "WebDAV file move (path traversal / DoS)",
    "COPY": "WebDAV file copy (info disclosure)",
    "MKCOL": "WebDAV collection creation",
    "PROPFIND": "WebDAV directory listing",
    "PROPPATCH": "WebDAV property modification",
    "LOCK": "WebDAV resource locking (DoS)",
    "UNLOCK": "WebDAV unlock (DoS)",
    "TRACE": "Cross-Site Tracing (XST)",
    "CONNECT": "proxy tunnelling (SSRF pivot)",
    "PATCH": "direct resource modification (verify auth)",
}


@register
class HttpMethodModule(Module):
    name = "http-methods"
    categories = [Category.MISCONFIG, Category.RECON]
    passive = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        resp = await ctx.client.request("OPTIONS", ctx.base_url, follow_redirects=True)
        if not resp.ok:
            return findings
        allow = (
            resp.headers.get("allow")
            or resp.headers.get("public")
            or resp.headers.get("accept-post")
            or ""
        )
        # Accept-Post only lists POST; treat as the only method if alone.
        if not allow and resp.headers.get("accept-post"):
            allow = "POST"
        methods = [m.strip().upper() for m in allow.split(",") if m.strip()] if allow else []
        ctx.recon["http_methods"] = methods

        if not methods:
            return findings

        # Always surface the discovered method set as recon.
        findings.append(
            Finding(
                category=Category.RECON,
                title=f"Server advertises {len(methods)} HTTP method(s): {', '.join(methods)}",
                severity=Severity.INFO,
                confidence="firm",
                url=resp.url,
                description=(
                    "An OPTIONS request returned an Allow / Public header listing "
                    "the HTTP methods the server accepts. This shapes which active "
                    "tests are worth running."
                ),
                evidence=f"OPTIONS {ctx.base_url} -> Allow: {allow}",
                remediation="Restrict the Allow header to methods the application actually uses.",
                module=self.name,
                verified=True,
            )
        )

        risky = [m for m in methods if m in RISKY_METHODS]
        if risky:
            sev = Severity.HIGH if ("PUT" in risky or "DELETE" in risky or "CONNECT" in risky) else Severity.MEDIUM
            details = "\n".join(f"- {m}: {RISKY_METHODS[m]}" for m in risky)
            findings.append(
                Finding(
                    category=Category.MISCONFIG,
                    title=f"Risky HTTP methods enabled: {', '.join(risky)}",
                    severity=sev,
                    confidence="firm",
                    url=resp.url,
                    description=(
                        "The server advertises HTTP methods that expand the attack "
                        "surface. Each can be abused as noted below; verify whether "
                        "they are actually functional (the Allow header is sometimes "
                        "stale) and gated by authentication."
                    ),
                    evidence=details,
                    remediation=(
                        "Disable WebDAV unless required; gate PUT/DELETE/CONNECT "
                        "behind strong auth; disable TRACE entirely."
                    ),
                    cwe="CWE-650",
                    module=self.name,
                    verified=True,
                )
            )

        # Cross-Site Tracing (XST): if TRACE is enabled, see whether the
        # response actually echoes the request. This is a passive probe --
        # we send a single TRACE request with a benign body.
        if "TRACE" in risky:
            trace_resp = await ctx.client.request(
                "TRACE", ctx.base_url, headers={"X-Bughound-Probe": "xst"}, follow_redirects=True
            )
            if trace_resp.ok and "X-Bughound-Probe" in trace_resp.text:
                findings.append(
                    Finding(
                        category=Category.MISCONFIG,
                        title="TRACE method reflects request headers (XST)",
                        severity=Severity.MEDIUM,
                        confidence="confirmed",
                        url=trace_resp.url,
                        description=(
                            "The server implements HTTP TRACE and echoes request headers "
                            "in the response body. Combined with XSS, this enables "
                            "Cross-Site Tracing to steal HttpOnly cookies."
                        ),
                        evidence=f"TRACE response body excerpt: {trace_resp.text[:200]!r}",
                        remediation="Disable TRACE on the web server (most servers default to off).",
                        cwe="CWE-489",
                        module=self.name,
                        verified=True,
                    )
                )
        return findings
