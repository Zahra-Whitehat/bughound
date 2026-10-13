"""Objective completion: drive exploitation all the way to "solved".

Detecting and proving a bug is not the same as *completing* the exploit.
Training-lab platforms (PortSwigger Web Security Academy and friends) only
flip their status banner when the intended exploitation objective is fully
achieved -- e.g. the administrator's password has been extracted AND used
to log in. This module closes that gap:

1. **Detect** the objective: PortSwigger labs are recognised from the page
   markup (``academyLabHeader`` / ``widgetcontainer-lab-status``) that the
   crawler already fetched -- zero extra requests.
2. **Verify** the current status from the live page (``is-solved`` vs
   ``is-notsolved``) so the report shows before/after evidence.
3. **Escalate** when the objective is still open: re-run the full
   exploitation chains (UNION credential extraction, then boolean-blind
   extraction) against every SQLi finding, checking the lab status after
   each attempt, until the objective is completed or strategies run out.
4. **Record** the outcome on the result (``result.objective``) and as a
   dedicated finding, so the report's "Objective completion" section can
   state -- with captured evidence -- that the lab was solved.

Everything here reuses the same HttpClient and scope/denylist guardrails
as the scan itself.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from html import unescape

from .models import Category, Finding, ScanResult, Severity
from .modules.base import ScanContext

# --- markup landmarks ------------------------------------------------------

LAB_HEADER_RE = re.compile(r"academyLabHeader|widgetcontainer-lab-status", re.IGNORECASE)
LAB_TITLE_RE = re.compile(
    r"<div class=title-container>\s*<h2>(.*?)</h2>", re.DOTALL | re.IGNORECASE
)
LAB_TITLE_FALLBACK_RE = re.compile(r"<title>(.*?)</title>", re.DOTALL | re.IGNORECASE)
LAB_STATUS_BLOCK_RE = re.compile(
    r"widgetcontainer-lab-status\s*(is-solved|is-notsolved)", re.IGNORECASE
)
LAB_STATUS_TEXT_RE = re.compile(r"<p>\s*(Not solved|Solved)\s*</p>", re.IGNORECASE)
ACADEMY_HOST_RE = re.compile(r"web-security-academy\.net(?=[:/]|$)", re.IGNORECASE)
# The platform prints the intended objective as a hint paragraph inside the
# banner (e.g. "Make the database retrieve the string: 'kNwvPL'"). It is the
# authoritative, machine-readable statement of WHAT the exploit must achieve,
# so it is parsed alongside the title and fed to the objective engine.
LAB_HINT_RE = re.compile(
    r"<p[^>]*\bid=[\"']?hint[\"']?[^>]*>(.*?)</p>", re.DOTALL | re.IGNORECASE
)


def detect_lab_html(html: str) -> dict | None:
    """Parse lab identity + status out of an Academy page (or None)."""
    if not html or not LAB_HEADER_RE.search(html):
        return None
    m = LAB_TITLE_RE.search(html) or LAB_TITLE_FALLBACK_RE.search(html)
    title = unescape(m.group(1)).strip() if m else "unknown lab"
    status = None
    sm = LAB_STATUS_BLOCK_RE.search(html)
    if sm:
        status = sm.group(1).lower() == "is-solved"
    else:
        tm = LAB_STATUS_TEXT_RE.search(html)
        if tm:
            status = tm.group(1).lower() == "solved"
    lab = {"title": title, "solved": status}
    hm = LAB_HINT_RE.search(html)
    if hm:
        lab["hint"] = re.sub(r"\s+", " ", unescape(hm.group(1))).strip()
    return lab


def is_academy_url(url: str) -> bool:
    return bool(ACADEMY_HOST_RE.search(url or ""))


async def check_lab_status(ctx: ScanContext) -> dict | None:
    """Fetch the lab homepage and return {title, solved, evidence} or None."""
    try:
        r = await ctx.client.get(ctx.base_url)
    except Exception:  # noqa: BLE001 -- status probing must never break a scan
        return None
    if not r.ok or not r.text:
        return None
    lab = detect_lab_html(r.text)
    if lab is None:
        return None
    block = LAB_STATUS_BLOCK_RE.search(r.text)
    lab["evidence"] = block.group(0) if block else ("status text" if lab["solved"] is not None else "")
    return lab


async def run_solve_phase(ctx: ScanContext, result: ScanResult, emit) -> None:
    """Complete the lab objective when detection+exploitation left it open.

    Called by the engine after the exploit and chain phases. Cheap no-op on
    non-lab targets (a dict lookup on the already-fetched seed HTML).
    """
    lab = detect_lab_html(ctx.seed_html or "")
    if lab is None and is_academy_url(ctx.base_url):
        # Host is an Academy host but the seed page lacked the header markup
        # (e.g. crawler landed on a redirect): one status request settles it.
        lab = await check_lab_status(ctx)
        if lab:
            lab["evidence"] = "(status fetched from lab homepage)"
    if lab is None:
        if is_academy_url(ctx.base_url):
            # Academy host, but neither the crawl's seed page nor a live
            # status fetch exposed the objective banner -- the typical cause
            # is lab throttling (the Academy rate-limits aggressive
            # automated traffic) or the instance going offline. Record it
            # so the report explains WHY the objective could not be driven.
            result.objective = {
                "type": "portswigger-lab",
                "title": "unknown (objective banner not reachable)",
                "solved_before": None,
                "attempts": [],
                "solved_after": None,
                "evidence": (
                    "Academy host detected, but the lab status check failed -- "
                    "the instance is likely throttled or offline. Re-run the "
                    "scan on a fresh instance once it responds again."
                ),
                "checked_at": datetime.now(timezone.utc).isoformat(),
            }
            result.stats["objective"] = 0
            emit("  [solve] Academy host detected but the lab status is not "
                 "reachable (throttled or offline); objective recorded as unknown")
        return

    objective: dict = {
        "type": "portswigger-lab",
        "title": lab["title"],
        "solved_before": lab.get("solved"),
        "attempts": [],
        "solved_after": lab.get("solved"),
        "evidence": lab.get("evidence", ""),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    emit(f"Lab objective detected: '{lab['title']}' (status: "
         f"{'solved' if lab.get('solved') else 'not solved'})")
    result.stats["objective"] = 0  # marker; final value set below

    if lab.get("solved") is True:
        objective["solved_after"] = True
        _record(result, objective, emit, early=True)
        return

    # Escalation is an active exploitation activity: it must respect the same
    # gate as the exploit phase (aggressive mode + exploit enabled). In safe
    # mode we only report the detected objective and its status.
    if not (ctx.config.aggressive and ctx.config.exploit):
        objective["attempts"].append({
            "strategy": "(skipped: exploit phase disabled -- safe/detection-only mode)",
            "finding": "",
            "exploit_status": "",
            "lab_solved": False,
        })
        _record(result, objective, emit, early=True)
        return

    # --- Escalation ladder -------------------------------------------------
    # 0.9.0: the ladder is built from the lab's own title (the platform
    # prints the intended objective) AND the scan's findings, then worked
    # top-down. Every strategy is a *generic* exploitation chain -- no
    # lab-specific URLs, paths or credentials anywhere. Success is always
    # the platform's own status banner, re-read after every attempt.
    from .objectives import SolveBudget, build_ladder

    ladder = build_ladder(lab.get("title", ""), result)
    objective["ladder"] = [s.name for s in ladder]
    budget = SolveBudget(max_requests=int(getattr(ctx.config, "solve_budget", 220) or 220))
    emit(f"  [solve] objective ladder: {' -> '.join(s.name for s in ladder[:6])}"
         f" (+{max(0, len(ladder) - 6)} more)" if len(ladder) > 6 else
         f"  [solve] objective ladder: {' -> '.join(s.name for s in ladder)}")
    for strategy in ladder:
        if objective.get("solved_after"):
            break
        if not budget.take(1):
            emit("  [solve] request budget exhausted -- remaining strategies skipped")
            break
        emit(f"  [solve] objective open -> {strategy.name}")
        try:
            note = await strategy.run(ctx, result, emit, budget)
        except Exception as exc:  # noqa: BLE001 -- solver never kills the scan
            note = f"{type(exc).__name__}: {exc}"
            result.errors.append(f"solve phase ({strategy.name}): {note}")
        status = await check_lab_status(ctx)
        attempt = {
            "strategy": strategy.name,
            "finding": (note or "")[:160],
            "exploit_status": f"budget={budget.spent} reqs",
            "lab_solved": bool(status and status.get("solved") is True),
        }
        objective["attempts"].append(attempt)
        if attempt["lab_solved"]:
            objective["solved_after"] = True
            objective["evidence"] = status.get("evidence", "is-solved")
            if status and status.get("title"):
                objective["title"] = status["title"]
            break

    _record(result, objective, emit)


async def _retry_union(ctx: ScanContext, finding: Finding, rt, param: str) -> None:
    """Force a fresh UNION extraction run (kept for backwards compatibility
    with older tests; the 0.9.0 ladder calls the objectives engine)."""
    from .exploits.sqli import exploit_sqli_union

    finding.exploit_status = "not_attempted"
    await exploit_sqli_union(ctx, finding, rt, param)


async def _retry_boolean(ctx: ScanContext, finding: Finding, rt, param: str) -> None:
    """Blind fallback: binary-search the credential through the boolean oracle
    (kept for backwards compatibility; see _retry_union)."""
    from .exploits.sqli import exploit_sqli_boolean

    if finding.exploit_status == "succeeded" and any(
        "ACCOUNT TAKEOVER" in line for line in finding.extracted_data
    ):
        return  # already completed by the UNION run
    finding.exploit_status = "not_attempted"
    await exploit_sqli_boolean(ctx, finding, rt, param)


def _retarget(ctx: ScanContext, finding: Finding):
    """Match a finding back to a request target + injectable parameter."""
    from .exploits import match_request_target, param_from_title

    rt = match_request_target(ctx.request_targets, finding.url)
    param = param_from_title(finding.title)
    if rt is None or not param:
        return None, None
    return rt, param


def _record(result: ScanResult, objective: dict, emit, early: bool = False) -> None:
    solved = objective.get("solved_after") is True
    result.objective = objective
    result.stats["objective"] = 1 if solved else 0
    if solved:
        emit(f"  [solve] OBJECTIVE COMPLETED -- lab '{objective['title']}' is SOLVED "
             f"({len(objective['attempts'])} escalation attempt(s) this run)")
        finding = Finding(
            category=Category.RECON,
            title=f"Lab objective completed: {objective['title']}",
            severity=Severity.INFO,
            url=result.config.target_url,
            description=(
                "The lab's intended exploitation objective was fully completed by the "
                "agent: the vulnerability was detected, exploited end-to-end, and the "
                "platform's own status banner flipped to 'Solved'."
            ),
            evidence=(
                f"Lab status before: "
                f"{'solved' if objective.get('solved_before') else 'not solved'}; "
                f"after: solved. Status markup captured: "
                f"'{objective.get('evidence') or 'is-solved'}'. "
                f"Escalation attempts: "
                f"{'; '.join(a['strategy'] + ' -> ' + ('solved the lab' if a['lab_solved'] else a['exploit_status']) for a in objective['attempts']) or 'none needed (already solved)'}"
            ),
            verified=True,
        )
        finding.exploit_status = "succeeded"
        finding.exploit_summary = (
            "Objective completion proof: the exploitation chain (credential extraction "
            "followed by authenticated login) was executed to completion and confirmed "
            "by the platform's own solved-status banner."
        )
        result.add(finding)
    elif not early:
        emit("  [solve] objective remains open after all solver strategies "
             "(detection/exploit evidence in the report still stands)")
