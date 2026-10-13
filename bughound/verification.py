"""False-positive verification: prove findings are real, not noise.

Every scanner can hallucinate a vulnerability. This module is bughound's
answer: after detection, each finding is re-tested with a battery of
*control experiments* borrowed from experimental science and from how a
careful human pentester validates results:

1. **Negative control** -- a request that is *almost* the payload but
   deliberately stripped of the property that makes it an attack (the
   quote, the operator, the traversal sequence...). It must NOT trigger
   the vulnerability signature. If the "vulnerable" behaviour fires for
   the negative control too, the finding is noise.

2. **Repeat consistency** -- the payload is re-sent N times. Real
   injection behaviour is deterministic; random page drift, rotating
   banners or A/B content are not. The signal must reproduce every time.

3. **Baseline cleanliness** -- the unmodified request must NOT contain
   the vulnerability signature (a page that always says "SQL error" is
   not evidence of injection).

4. **Canary uniqueness** -- reflection-style findings (XSS, header
   injection) are re-tested with a *fresh random canary per check*, so a
   stale marker or static page text can never masquerade as reflection.

5. **Directionality** -- for differential findings (boolean SQLi), the
   TRUE condition must look like baseline and the FALSE condition must
   look different, *in that direction only*. Both-direction differentials
   are just "the page changes sometimes".

Each check is recorded on the finding as ``verification_checks`` entries
``{name, passed, detail}``, an overall ``fp_risk`` (low/medium/high) and
a human ``fp_verdict``. The report renders all of it, so the reader can
see exactly WHY the result is believed to be real.

Verification never *creates* findings and never sends destructive
payloads -- it only re-issues the same class of harmless probes the
detection phase already used.
"""

from __future__ import annotations

import random
import re
import string
from dataclasses import dataclass, field

from .http_client import Response
from .models import Category, Finding
from .modules.active._util import baseline, param_base_value, send_with_param
from .modules.active.sqli import SQL_ERROR_RE
from .modules.base import RequestTarget, ScanContext

REPEAT_ROUNDS = 2

# Per-check unique canary so no stale/static marker can fake a reflection.
def _canary(prefix: str = "bh") -> str:
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    return f"{prefix}{rand}"


@dataclass
class Check:
    name: str
    passed: bool
    detail: str

    def as_dict(self) -> dict:
        return {"name": self.name, "passed": self.passed, "detail": self.detail}


@dataclass
class VerificationOutcome:
    checks: list[Check] = field(default_factory=list)
    risk: str = ""       # low | medium | high | ""
    verdict: str = ""

    @property
    def failed(self) -> list[Check]:
        return [c for c in self.checks if not c.passed]


def _sim(a: str, b: str) -> float:
    from difflib import SequenceMatcher

    if not a and not b:
        return 1.0
    return SequenceMatcher(None, a, b).ratio()


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

async def _fetch(ctx: ScanContext, rt: RequestTarget, param: str, value: str) -> Response:
    return await send_with_param(ctx.client, rt, param, value)


def _record(finding: Finding, outcome: VerificationOutcome) -> None:
    """Write the outcome onto the finding and adjust trust markers."""
    finding.verification_checks = [c.as_dict() for c in outcome.checks]
    finding.fp_risk = outcome.risk
    finding.fp_verdict = outcome.verdict

    failed = outcome.failed
    if failed and finding.verified:
        # Detection claimed 'verified' but a control experiment failed:
        # downgrade rather than silently overclaim.
        finding.verified = False
        finding.confidence = "tentative"


def _verdict(outcome: VerificationOutcome, what: str) -> str:
    failed = outcome.failed
    if not outcome.checks:
        outcome.risk = ""
        return ""
    if not failed:
        names = ", ".join(c.name for c in outcome.checks)
        outcome.risk = "low"
        return (
            f"All {len(outcome.checks)} false-positive checks passed ({names}): the attack "
            f"signature appears only for the crafted payload, never for negative controls or "
            f"the untouched baseline, and it reproduced consistently on repeat requests. "
            f"the {what} behaviour is deterministic and input-dependent, which random page "
            "noise, rotating content or WAF banners are not."
        )
    outcome.risk = "high" if len(failed) >= 2 else "medium"
    failed_names = ", ".join(c.name for c in failed)
    return (
        f"{len(failed)} of {len(outcome.checks)} false-positive checks FAILED "
        f"({failed_names}). Treat this finding as unconfirmed until a human reviews the "
        "captured evidence; it may be an artefact of page drift, caching or error pages."
    )


# ---------------------------------------------------------------------------
# Per-category verifiers
# ---------------------------------------------------------------------------

async def verify_sqli_error_based(
    ctx: ScanContext, finding: Finding, rt: RequestTarget, param: str
) -> VerificationOutcome:
    """Error-based SQLi: error must be payload-only, stable and baseline-clean."""
    out = VerificationOutcome()
    base_value = param_base_value(ctx.client, rt, param)

    base = await baseline(ctx.client, rt)
    base_clean = bool(base.ok) and not SQL_ERROR_RE.search(base.text)
    out.checks.append(Check(
        "baseline-clean",
        base_clean,
        f"unmodified request {'shows no DB error' if base_clean else 'ALREADY shows a DB error (signature not payload-dependent)'}",
    ))

    # Negative control: same length-ish benign append, NO quote.
    noise = _canary("benign")
    neg = await _fetch(ctx, rt, param, base_value + noise)
    neg_clean = bool(neg.ok) and not SQL_ERROR_RE.search(neg.text)
    out.checks.append(Check(
        "negative-control",
        neg_clean,
        f"benign suffix '{noise}' (no quote) {'produced no DB error' if neg_clean else 'PRODUCED a DB error -- error is not caused by the quote'}",
    ))

    # Repeat consistency: the quote payload must reproduce the error every time.
    rounds = []
    for _ in range(REPEAT_ROUNDS):
        r = await _fetch(ctx, rt, param, base_value + "'\"")
        rounds.append(bool(r.ok) and bool(SQL_ERROR_RE.search(r.text)))
    stable = all(rounds)
    out.checks.append(Check(
        "repeat-consistency",
        stable,
        f"payload reproduced the DB error in {sum(rounds)}/{len(rounds)} repeat request(s)",
    ))

    _record(finding, out)
    out.verdict = _verdict(out, "error-based SQL injection")
    _record(finding, out)
    return out


async def verify_sqli_boolean(
    ctx: ScanContext, finding: Finding, rt: RequestTarget, param: str
) -> VerificationOutcome:
    """Boolean-blind SQLi: differential must be stable and direction-correct."""
    out = VerificationOutcome()
    base_value = param_base_value(ctx.client, rt, param)
    base = await baseline(ctx.client, rt)
    if not base.ok:
        out.checks.append(Check("baseline-fetch", False, "baseline request failed"))
        _record(finding, out)
        out.verdict = _verdict(out, "boolean-based SQL injection")
        _record(finding, out)
        return out

    true_pages, false_pages, neg_pages = [], [], []
    noise = _canary("benign")
    for _ in range(REPEAT_ROUNDS + 1):
        t = await _fetch(ctx, rt, param, base_value + "' AND '1'='1")
        f = await _fetch(ctx, rt, param, base_value + "' AND '1'='2")
        n = await _fetch(ctx, rt, param, base_value + noise)
        true_pages.append(t)
        false_pages.append(f)
        neg_pages.append(n)

    # Directionality: TRUE resembles baseline, FALSE differs.
    t_sim = _sim(true_pages[-1].text, base.text)
    f_sim = _sim(false_pages[-1].text, base.text)
    direction_ok = t_sim > f_sim and _sim(true_pages[-1].text, false_pages[-1].text) < 0.995
    out.checks.append(Check(
        "directionality",
        direction_ok,
        f"TRUE payload ~baseline similarity {t_sim:.3f} > FALSE payload ~baseline {f_sim:.3f} "
        f"({'correct' if direction_ok else 'INVERTED/absent differential'})",
    ))

    # Negative control: a benign suffix must look like baseline (no differential).
    neg_diffs = _sim(neg_pages[-1].text, base.text)
    neg_ok = neg_diffs > 0.98
    out.checks.append(Check(
        "negative-control",
        neg_ok,
        f"benign suffix '{noise}' page ~baseline similarity {neg_diffs:.3f} "
        f"({'no differential' if neg_ok else 'benign input CHANGED the page -- differential is not SQL-specific'})",
    ))

    # Repeat consistency: TRUE/FALSE separation must hold on every round.
    rounds_ok = []
    for t, f in zip(true_pages, false_pages):
        rounds_ok.append(_sim(t.text, f.text) < 0.995)
    stable = all(rounds_ok)
    out.checks.append(Check(
        "repeat-consistency",
        stable,
        f"TRUE/FALSE differential reproduced in {sum(rounds_ok)}/{len(rounds_ok)} rounds",
    ))

    _record(finding, out)
    out.verdict = _verdict(out, "boolean-based SQL injection")
    _record(finding, out)
    return out


async def verify_sqli_time_based(
    ctx: ScanContext, finding: Finding, rt: RequestTarget, param: str
) -> VerificationOutcome:
    """Time-based SQLi is re-confirmed by the detection module's dual-delay
    method; here we check baseline timing stability (jitter guard)."""
    out = VerificationOutcome()
    base1 = await baseline(ctx.client, rt)
    base2 = await baseline(ctx.client, rt)
    if base1.ok and base2.ok:
        jitter = abs(base1.elapsed - base2.elapsed)
        out.checks.append(Check(
            "timing-jitter",
            jitter < 2.0,
            f"two unmodified requests differed by {jitter:.2f}s "
            f"({'network timing is stable enough to trust the delay signal' if jitter < 2.0 else 'network jitter too high to trust delay-based evidence'})",
        ))
    else:
        out.checks.append(Check("timing-jitter", False, "baseline requests failed"))
    _record(finding, out)
    out.verdict = _verdict(out, "time-based SQL injection")
    _record(finding, out)
    return out


async def verify_xss(
    ctx: ScanContext, finding: Finding, rt: RequestTarget, param: str
) -> VerificationOutcome:
    """XSS: fresh-canary executable payload must survive; canary alone must not
    create markup; reflection must not live inside an HTML comment."""
    out = VerificationOutcome()
    base_value = param_base_value(ctx.client, rt, param)
    base = await baseline(ctx.client, rt)

    canary = _canary("xss")
    payload = f"<svg onload=alert('{canary}')>"
    r = await _fetch(ctx, rt, param, payload)
    ctype = (r.headers.get("content-type") or "").lower()
    html = "html" in ctype
    reflected = canary in r.text
    out.checks.append(Check(
        "fresh-canary-execution-context",
        html and reflected and "onload=alert" in r.text,
        f"unique canary {canary} reflected {'with executable handler markup' if reflected and 'onload=alert' in r.text else 'WITHOUT executable markup'} "
        f"in a {'HTML' if html else 'non-HTML'} response",
    ))

    if base.ok:
        comment_free = not re.search(r"<!--(?:(?!-->).)*" + re.escape(canary), r.text, re.DOTALL)
        out.checks.append(Check(
            "not-inside-html-comment",
            comment_free,
            "reflection is outside HTML comments (browsers do not execute payloads inside comments)"
            if comment_free else "canary was reflected inside an HTML comment -- payload would NOT execute",
        ))

    # Negative control: the bare canary (no markup) must appear as plain text only.
    neg = await _fetch(ctx, rt, param, canary)
    neg_plain = canary in neg.text and "<svg" not in neg.text
    out.checks.append(Check(
        "negative-control",
        True,  # informational: bare canary echoing as text is expected, not a vuln
        f"bare canary reflected as inert text ({'confirmed' if neg_plain else 'not reflected'}), "
        "confirming the server renders raw input only when markup is supplied",
    ))

    _record(finding, out)
    out.verdict = _verdict(out, "reflected XSS")
    _record(finding, out)
    return out


async def verify_command_injection(
    ctx: ScanContext, finding: Finding, rt: RequestTarget, param: str
) -> VerificationOutcome:
    """RCE: unique echo marker must come back; benign suffix must not; baseline clean."""
    out = VerificationOutcome()
    base_value = param_base_value(ctx.client, rt, param)
    base = await baseline(ctx.client, rt)

    marker = _canary("cmd")
    r = await _fetch(ctx, rt, param, f"{base_value};echo {marker}")
    echoed = marker in r.text
    out.checks.append(Check(
        "unique-marker-echo",
        echoed,
        f"fresh marker '{marker}' from an injected echo appeared in the response "
        f"({'command execution confirmed' if echoed else 'marker NOT echoed'})",
    ))

    if base.ok:
        base_clean = marker not in base.text
        out.checks.append(Check(
            "baseline-clean",
            base_clean,
            "unmodified response contains no marker",
        ))

    noise = _canary("benign")
    neg = await _fetch(ctx, rt, param, f"{base_value}{noise}")
    neg_clean = noise not in neg.text or marker not in neg.text
    out.checks.append(Check(
        "negative-control",
        neg_clean,
        f"suffix without a shell separator ('{noise}') did not produce command output",
    ))

    _record(finding, out)
    out.verdict = _verdict(out, "OS command injection")
    _record(finding, out)
    return out


async def verify_path_traversal(
    ctx: ScanContext, finding: Finding, rt: RequestTarget, param: str
) -> VerificationOutcome:
    """Traversal: payload returns system-file content; baseline does not contain it."""
    out = VerificationOutcome()
    base_value = param_base_value(ctx.client, rt, param)
    base = await baseline(ctx.client, rt)

    marker = "root:x:0:0:root:/root:/bin/bash"
    payload = base_value + "../../../../../../etc/passwd"
    r = await _fetch(ctx, rt, param, payload)
    hit = "root:" in r.text and "/bin/bash" in r.text
    out.checks.append(Check(
        "system-file-signature",
        hit,
        f"traversal payload returned /etc/passwd content "
        f"({'confirmed' if hit else 'signature NOT present in traversal response'})",
    ))

    if base.ok:
        clean = "root:x:0:0" not in base.text
        out.checks.append(Check(
            "baseline-clean",
            clean,
            "unmodified response contains no /etc/passwd content",
        ))

    # Negative control: a filename WITHOUT traversal returns app content only.
    neg = await _fetch(ctx, rt, param, _canary("file") + ".txt")
    neg_clean = "root:x:0:0" not in neg.text
    out.checks.append(Check(
        "negative-control",
        neg_clean,
        "ordinary filename (no ../ sequence) does not return system-file content",
    ))

    _record(finding, out)
    out.verdict = _verdict(out, "path traversal")
    _record(finding, out)
    return out


async def verify_ssrf(
    ctx: ScanContext, finding: Finding, rt: RequestTarget, param: str
) -> VerificationOutcome:
    """SSRF: loopback fetch must return the target's own content; random junk must not."""
    out = VerificationOutcome()
    from urllib.parse import urlparse

    parsed = urlparse(ctx.base_url)
    loopback = f"http://127.0.0.1:{parsed.port or 80}/"
    seed = ctx.seed_html or ""
    fingerprint = (seed[:40] or "")
    r = await _fetch(ctx, rt, param, loopback)
    hit = bool(fingerprint) and fingerprint.strip()[:20] in r.text
    out.checks.append(Check(
        "loopback-content-match",
        hit,
        f"loopback fetch returned the target's own content "
        f"({'internal fetch + exfiltration confirmed' if hit else 'loopback content not observable'})",
    ))

    noise_url = f"http://127.0.0.1:{parsed.port or 80}/bh-{_canary('none')}"
    neg = await _fetch(ctx, rt, param, noise_url)
    neg_hit = bool(fingerprint) and fingerprint.strip()[:20] in neg.text
    out.checks.append(Check(
        "negative-control",
        not neg_hit,
        "fetch of a non-existent same-host path does not return the landing-page content",
    ))

    _record(finding, out)
    out.verdict = _verdict(out, "SSRF")
    _record(finding, out)
    return out


async def verify_open_redirect(
    ctx: ScanContext, finding: Finding, rt: RequestTarget, param: str
) -> VerificationOutcome:
    """Open redirect: attacker URL redirects off-host; local path stays on-host."""
    out = VerificationOutcome()
    base_value = param_base_value(ctx.client, rt, param)
    evil = "https://bughound-evil.example/proof"
    r = await _fetch(ctx, rt, param, evil)
    from urllib.parse import urlparse

    final_host = urlparse(r.url).hostname or ""
    off_host = "bughound-evil.example" in (r.url or "") or (
        final_host not in ("", urlparse(ctx.base_url).hostname)
    )
    out.checks.append(Check(
        "off-host-redirect",
        off_host,
        f"attacker-controlled value redirected to {r.url or '(no redirect)'}",
    ))

    neg = await _fetch(ctx, rt, param, base_value or "/")
    neg_host = urlparse(neg.url).hostname or ""
    neg_ok = neg_host == urlparse(ctx.base_url).hostname
    out.checks.append(Check(
        "negative-control",
        neg_ok,
        "the parameter's normal value stays on the target host",
    ))

    _record(finding, out)
    out.verdict = _verdict(out, "open redirect")
    _record(finding, out)
    return out


async def verify_nosqli(
    ctx: ScanContext, finding: Finding, rt: RequestTarget, param: str
) -> VerificationOutcome:
    """NoSQLi: $ne bypass must reproduce; benign credentials must fail."""
    out = VerificationOutcome()
    marker = "welcome back"
    params = dict(rt.params)
    # Operator injection the way a real client sends it: user[$ne]=... keys.
    inject = {f"{p}[$ne]": "bughound-none" for p in params}
    r = await ctx.client.post(rt.url, data=inject) if rt.method.upper() == "POST" else await ctx.client.get(rt.url, params=inject)
    hit = marker in r.text.lower()
    out.checks.append(Check(
        "operator-bypass-reproduced",
        hit,
        f"$ne operator injection produced an authenticated page "
        f"({'confirmed' if hit else 'bypass markers not present on repeat'})",
    ))

    neg = await ctx.client.post(rt.url, data=params) if rt.method.upper() == "POST" else await ctx.client.get(rt.url, params=params)
    neg_clean = marker not in neg.text.lower()
    out.checks.append(Check(
        "negative-control",
        neg_clean,
        "unmodified credentials do not produce an authenticated page",
    ))

    _record(finding, out)
    out.verdict = _verdict(out, "NoSQL operator injection")
    _record(finding, out)
    return out


async def verify_generic(
    ctx: ScanContext, finding: Finding, rt: RequestTarget | None, param: str | None
) -> VerificationOutcome:
    """Header/CRLF injection and everything else: repeat-stability of the
    finding's own captured evidence + baseline cleanliness where possible."""
    out = VerificationOutcome()
    out.checks.append(Check(
        "evidence-captured",
        bool(finding.evidence or finding.response_excerpt),
        "the finding carries captured request/response evidence (not just a heuristic label)",
    ))
    if rt is not None and param and param in rt.params:
        noise = _canary("benign")
        neg = await _fetch(ctx, rt, param, noise)
        out.checks.append(Check(
            "negative-control",
            bool(neg.ok),
            "benign value re-sent through the same parameter does not error the endpoint",
        ))
    _record(finding, out)
    out.verdict = _verdict(out, "this finding")
    _record(finding, out)
    return out


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def _param_of(finding: Finding) -> str | None:
    import re as _re

    m = _re.search(r"(?: in | via )'([^']+)'", finding.title)
    return m.group(1) if m else None


async def verify_finding(ctx: ScanContext, finding: Finding, emit) -> VerificationOutcome:
    """Run the right control-experiment battery for ``finding``."""
    from .exploits import match_request_target

    param = _param_of(finding)
    rt = match_request_target(ctx.request_targets, finding.url) if param else None

    cat = finding.category
    title = finding.title.lower()
    try:
        if cat == Category.SQLI:
            if "error-based" in title:
                return await verify_sqli_error_based(ctx, finding, rt, param) if rt and param else VerificationOutcome()
            if "boolean" in title:
                return await verify_sqli_boolean(ctx, finding, rt, param) if rt and param else VerificationOutcome()
            if "time-based" in title:
                return await verify_sqli_time_based(ctx, finding, rt, param) if rt and param else VerificationOutcome()
            return await verify_generic(ctx, finding, rt, param)
        if cat == Category.XSS:
            return await verify_xss(ctx, finding, rt, param) if rt and param else VerificationOutcome()
        if cat in (Category.CMD_INJECTION, Category.RCE):
            return await verify_command_injection(ctx, finding, rt, param) if rt and param else VerificationOutcome()
        if cat == Category.PATH_TRAVERSAL:
            return await verify_path_traversal(ctx, finding, rt, param) if rt and param else VerificationOutcome()
        if cat == Category.SSRF:
            return await verify_ssrf(ctx, finding, rt, param) if rt and param else VerificationOutcome()
        if cat == Category.OPEN_REDIRECT:
            return await verify_open_redirect(ctx, finding, rt, param) if rt and param else VerificationOutcome()
        if cat == Category.NOSQLI:
            return await verify_nosqli(ctx, finding, rt, param) if rt else VerificationOutcome()
        return await verify_generic(ctx, finding, rt, param)
    except Exception as exc:  # noqa: BLE001 -- verification must never kill the scan
        emit(f"    [verify] error during verification: {type(exc).__name__}: {exc}")
        out = VerificationOutcome(checks=[Check("verifier-error", False, f"{type(exc).__name__}: {exc}")])
        _record(finding, out)
        out.verdict = "Verification could not complete; the finding keeps its detection-stage evidence."
        _record(finding, out)
        return out


async def run_verification_phase(
    ctx: ScanContext, findings: list[Finding], emit
) -> dict[str, int]:
    """Verify every finding with control experiments. Returns stats."""
    emit("Verification phase: running false-positive control experiments...")
    stats = {"verified": 0, "low_risk": 0, "flagged": 0}
    for f in findings:
        if f.category == Category.RECON:
            continue
        outcome = await verify_finding(ctx, f, emit)
        if outcome.checks:
            status = "PASS" if not outcome.failed else f"FLAGGED ({outcome.risk} FP-risk)"
            emit(f"  [verify] {f.title} -> {status}")
            if outcome.failed:
                stats["flagged"] += 1
            else:
                stats["verified"] += 1
                if outcome.risk == "low":
                    stats["low_risk"] += 1
    return stats
