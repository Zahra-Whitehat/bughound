"""Scan orchestrator: authorization -> crawl -> modules -> external tools.

0.7 pipeline (Sn1per modes x Bug-Bounty-Agents squads)::

    authorize -> apply mode (stealth|normal|aggressive|nuke)
      -> crawl
      -> phase 1: RECON + CONFIG squads (passive; attack-surface mapping)
      -> attack planner (aggressive): recon-informed plan stored in result.plan
      -> phase 2: INJECTION + ACCESS squads (active payloads)
      -> exploit phase (aggressive): per-finding impact proofs
      -> chain phase (aggressive): exploit-chainer combines findings
      -> verification phase: control experiments on non-exploited findings
      -> code mapping -> external tools -> report
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from urllib.parse import urlparse

from . import integrations
from .agents import build_attack_plan, run_chain_phase, split_by_phase
from .authorization import Scope, authorize
from .codemapper import map_all_findings
from .crawler import crawl
from .exploits import run_exploit_phase
from .http_client import HttpClient, lab_dead_response
from .models import Category, Finding, ScanConfig, ScanResult, Severity, Target
from .modes import apply_mode
from .modules.base import RequestTarget, ScanContext, build_modules
from .solving import is_academy_url, run_solve_phase
from .verification import run_verification_phase

# Number of dead-lab gateway responses tolerated before the scan declares
# the instance dead and stops. Small on purpose: a live lab NEVER produces
# this signature, so even 3 hits means the backend is gone.
LAB_DEATH_THRESHOLD = 3


class _LabDiedError(Exception):
    """Internal control-flow: the lab instance died mid-scan. The guard that
    raises it has already emitted the expired-lab banner and recorded the
    error on the result; run_scan catches this to unwind cleanly."""


def emit_expired_lab_banner(emit, *, reason: str, lab_url: str = "") -> None:
    """Print the unmissable EXPIRED-LAB verdict.

    1.1.0: the shipped 1.0.0 banner lived inside a branch that could never
    fire (the probe accepted ANY response -- including the academy gateway's
    504 'cannot reach the lab backend' page -- as 'reachable'). Dead labs
    therefore produced a long silent module storm, zero findings and no
    explanation, which users read as 'the solver does not work'. This banner
    is now printed on every dead-lab path: pre-flight, mid-run and solve.
    """
    lines = [
        "",
        "  ================================================================",
        "  XXX  LAB INSTANCE IS DEAD / EXPIRED / STOPPED  XXX",
        f"  XXX  ({reason})",
        "  ================================================================",
        "  The PortSwigger gateway is answering, but it CANNOT REACH the",
        "  lab backend. The instance is gone. No scanner and no exploit",
        "  can solve a dead lab -- this is not a solver failure.",
        "",
        "  WHAT TO DO:",
        "   1. Open the lab page on portswigger.net and click",
        "      'Access the lab' (or 'Restart the lab').",
        "   2. Copy the NEW url from the browser address bar -- every",
        "      fresh instance gets a NEW random subdomain:",
        "      https://<32-hex>.web-security-academy.net/",
        "   3. Verify it is alive:  python -m bughound check '<NEW-URL>'",
        "   4. Then solve it:       python -m bughound scan '<NEW-URL>' \\",
        "                             --aggressive --i-am-authorized \\",
        "                             --timeout 60 --solve-budget 300",
        "",
        "  TIP: keep the lab browser tab open while scanning -- Academy",
        "  instances stop shortly after the browser session ends.",
        "  ================================================================",
        "",
    ]
    if lab_url:
        lines.insert(3, f"  dead instance: {lab_url}")
    for line in lines:
        emit(line)


def _make_target(url: str, note: str) -> Target:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    scheme = parsed.scheme or "http"
    port = parsed.port or (443 if scheme == "https" else 80)
    return Target(
        url=url,
        scheme=scheme,
        host=parsed.hostname or "",
        port=port,
        authorized=True,
        authorization_note=note,
    )


async def _probe_seed(client: HttpClient, url: str, emit) -> tuple[bool, str, bool]:
    """Pre-flight the target URL with a single GET.

    Returns ``(ok, reason, dead_lab)``. On failure ``reason`` is a
    human-readable string the operator can act on and ``dead_lab`` is True
    when the response carries the academy gateway's definitive
    'cannot connect to the lab backend' signature. We do this BEFORE the
    main crawl so we can:

      1. Detect a slow / asleep target (PortSwigger labs, serverless cold
         starts) early and retry once with a longer per-request timeout.
      2. Distinguish 'lab stopped/expired' (504 + gateway signature) from
         ordinary transport errors -- 1.0.0 treated any response as
         'reachable', so dead labs sailed through the probe and the scan
         burned minutes on a corpse with no explanation.
      3. Surface a TLS error, DNS error, or 4xx/5xx at the very top of the
         scan log instead of letting the crawl silently return "0 URLs"
         and every module silently fail afterwards.
    """
    resp = await client.get(url, follow_redirects=True)
    if resp.error:
        return False, resp.error, False
    if lab_dead_response(resp):
        return (
            False,
            f"the gateway cannot reach the lab backend (HTTP {resp.status}: "
            "instance stopped or expired)",
            True,
        )
    if not resp.status_ok:
        return False, f"HTTP {resp.status}", False
    return True, "", False


async def run_scan(
    config: ScanConfig,
    scope: Scope,
    confirmed: bool,
    progress=None,
) -> ScanResult:
    """Run a full scan. Raises AuthorizationError if the target is out of scope."""

    def emit(msg: str) -> None:
        if progress:
            progress(msg)

    note = authorize(config.target_url, scope, confirmed)
    target = _make_target(config.target_url, note)
    result = ScanResult(target=target, config=config)

    # Sn1per-style modes: expand the named mode into the boolean knobs the
    # rest of the pipeline reads. Empty mode = legacy flag behaviour kept.
    profile = apply_mode(config, config.mode)
    if profile:
        emit(f"Mode {profile.mode}: {profile.description}.")

    client = HttpClient(
        timeout=config.timeout,
        user_agent=config.user_agent,
        extra_headers=config.extra_headers,
        blocked=scope.url_denied,
    )
    try:
        if scope.denied_hosts or scope.denied_urls:
            emit(
                f"Denylist active: {len(scope.denied_hosts)} host pattern(s), "
                f"{len(scope.denied_urls)} URL prefix(es) will never be contacted."
            )

        # Pre-flight probe: catch unreachable / asleep / TLS-broken targets
        # before the crawl. This is the fix for the silent "0 URLs" case.
        emit(f"Probing target {config.target_url} (timeout {config.timeout}s)...")
        ok, reason, dead_lab = await _probe_seed(client, config.target_url, emit)
        if not ok:
            # First probe failed. The most common cause for an authorized
            # target is a sleeping lab / cold start (PortSwigger academy,
            # serverless) that wakes up on the first hit. Retry once with
            # a longer timeout before giving up -- but a definitive dead-lab
            # signature is final: the gateway CANNOT reach the backend, no
            # retry will resurrect it.
            if dead_lab:
                emit(f"  probe verdict: {reason}")
            else:
                emit(f"  initial probe failed: {reason}")
                emit("  retrying once with 2x timeout (target may be waking up)...")
                # Temporarily raise the timeout on the underlying httpx client.
                old_timeout = client._client.timeout
                try:
                    client._client.timeout = config.timeout * 2
                    ok, reason, dead_lab = await _probe_seed(
                        client, config.target_url, emit
                    )
                finally:
                    client._client.timeout = old_timeout
        if not ok:
            # Target still unreachable -- record a clear top-of-scan error
            # so the operator knows exactly what to fix, instead of running
            # 18 modules against an empty context and producing nothing.
            msg = (
                f"Target unreachable after retry: {reason}. "
                "Suggestions: (1) open the URL in a browser to confirm it is "
                "live; (2) pass --timeout 60 (labs / serverless may need >15s "
                "to wake up); (3) pass --user-agent '<browser UA>' if the host "
                "blocks non-browser agents; (4) verify the host is in your "
                "authorized scope."
            )
            if is_academy_url(config.target_url):
                msg += (
                    " (5) PORTSWIGGER ACADEMY LABS EXPIRE: if this instance was "
                    "started more than ~2 hours ago it is DEAD -- spawn a FRESH "
                    "lab instance and re-run this scan against the new URL. "
                    "No tool can solve an expired instance."
                )
            if dead_lab or (is_academy_url(config.target_url) and not ok):
                emit_expired_lab_banner(
                    emit,
                    reason=reason,
                    lab_url=config.target_url,
                )
            result.errors.append(msg)
            result.stats["lab_dead"] = True
            emit("Target unreachable -- aborting scan (see verdict above).")
            return result
        emit("  probe OK, target is reachable. Crawling...")

        urls, request_targets, seed_html, seed_headers = await crawl(
            client,
            config.target_url,
            config.max_urls,
            config.max_depth,
            is_denied=scope.url_denied,
            log=emit,
        )
        ctx = ScanContext(
            client=client,
            config=config,
            target=target,
            base_url=config.target_url,
            urls=urls,
            request_targets=request_targets,
            seed_html=seed_html,
            seed_headers=seed_headers,
            log=emit,
        )
        result.stats = {"urls_crawled": len(urls), "injectable_targets": len(request_targets)}
        emit(f"Discovered {len(urls)} URLs, {len(request_targets)} injectable targets.")

        # Direct-exploit mode: --exploit-endpoint URLs are registered as
        # request targets and seeded as findings so the exploit phase works
        # them even when the crawler cannot see the parameter (cookie-only
        # labs, non-linked endpoints, obfuscated HTML...).
        if config.exploit_endpoints:
            _register_direct_targets(config, ctx, result, emit)

        modules = build_modules(config)
        sem = asyncio.Semaphore(max(1, config.concurrency))

        async def run_module(mod):
            async with sem:
                emit(f"Running module: {mod.name}")
                try:
                    return mod.name, await mod.run(ctx)
                except Exception as exc:  # noqa: BLE001
                    result.errors.append(f"{mod.name}: {type(exc).__name__}: {exc}")
                    return mod.name, []

        async def run_module_group(group: list, label: str) -> None:
            if label:
                emit(f"-- {label} ({len(group)} modules) --")
            for name, findings in await asyncio.gather(*(run_module(m) for m in group)):
                result.modules_run.append(name)
                for f in findings:
                    result.add(f)
            # Merge any structured reconnaissance data the modules wrote into
            # the shared context (best-effort; see 0.6 note below).
            result.recon.update(ctx.recon)

        # Bug-Bounty-Agents phase order: recon/config squads first so the
        # planner has real attack-surface facts to reason about.
        # --- mid-run lab-death guard (1.1.0) -----------------------------
        # A lab can die WHILE the scan runs (browser tab closed, instance
        # expired). From that moment every request returns the gateway's
        # 'cannot reach the backend' page. Instead of grinding on, check the
        # client's death counter between phases and stop loudly.
        async def guard_lab_alive(stage: str) -> None:
            if client.lab_death_events >= LAB_DEATH_THRESHOLD:
                emit(
                    f"  the lab instance stopped answering mid-scan ({stage}: "
                    f"{client.lab_death_events} gateway 'backend unreachable' "
                    "responses) -- remaining stages skipped."
                )
                emit_expired_lab_banner(
                    emit,
                    reason="instance died during the scan (HTTP gateway cannot "
                    "reach the lab backend)",
                    lab_url=config.target_url,
                )
                result.errors.append(
                    f"Lab instance died mid-scan at stage '{stage}': the PortSwigger "
                    "gateway reports it cannot reach the lab backend. The instance "
                    "is expired/stopped -- restart the lab and re-run against the "
                    "NEW url. No tool can solve a dead instance."
                )
                result.stats["lab_dead"] = True
                raise _LabDiedError()

        phase1, phase2 = split_by_phase(modules)
        await run_module_group(phase1, "Phase 1: recon + config squads")
        await guard_lab_alive("after phase 1")

        # Attack planner (attack-planner/threat-modeler persona): turn the
        # recon facts into a plan that steers the hunting squads and gives
        # the report its "Attack plan" section.
        if config.aggressive and result.recon:
            plan = build_attack_plan(result.recon, aggressive=config.aggressive)
            result.plan = plan
            emit(
                f"Attack plan: {len(plan.get('focus_areas', []))} focus area(s), "
                f"{len(plan.get('tech_notes', []))} tech note(s)"
                + (f", WAF: {plan['waf']['name']}" if plan.get("waf") else "")
            )
            for area in plan.get("focus_areas", [])[:5]:
                emit(f"  [plan] focus: {area['area']} -- {area['why']}")

        await run_module_group(phase2, "Phase 2: hunting squads")
        result.recon.update(ctx.recon)
        await guard_lab_alive("after phase 2")

        # Exploit phase: when aggressive mode is on (and not disabled via
        # --no-exploit), re-target each finding with a safe proof exploit so
        # the report demonstrates real impact instead of just asserting it.
        # Runs inside the same client/scope guardrails as everything else.
        if config.aggressive and config.exploit and result.findings:
            await run_exploit_phase(ctx, result.findings, emit)
        await guard_lab_alive("after exploit phase")

        # Chain phase (exploit-chainer persona): combine proven findings into
        # attack chains whose combined impact exceeds the sum of the parts.
        # Every chain is recorded with full provenance (chain_of fingerprints)
        # and only ever re-uses the safe primitives already exercised above.
        # Gated on the same exploit switch as the exploit phase: --no-exploit
        # (detection-only runs) must leave findings completely untouched.
        if config.aggressive and config.exploit and result.findings:
            try:
                chains = await run_chain_phase(ctx, result, emit)
                if chains:
                    result.stats["chains"] = chains
            except Exception as exc:  # noqa: BLE001 -- chain failures never kill the scan
                result.errors.append(f"chain phase: {type(exc).__name__}: {exc}")

        # Solve phase (0.7.1): when the target is a training lab (PortSwigger
        # Academy & friends), drive the exploitation to full objective
        # completion -- e.g. extract the administrator password AND log in --
        # and verify the platform's own "solved" banner. Detection and proof
        # alone are not the goal; completing the exploit is.
        await guard_lab_alive("before solve phase")
        try:
            await run_solve_phase(ctx, result, emit)
        except Exception as exc:  # noqa: BLE001 -- solver failures never kill the scan
            result.errors.append(f"solve phase: {type(exc).__name__}: {exc}")
        await guard_lab_alive("after solve phase")

        # False-positive verification: control experiments (negative
        # controls, repeat consistency, baseline cleanliness, fresh
        # canaries) for every finding the exploit phase could NOT prove --
        # a succeeded exploit is its own false-positive disproof.
        if config.aggressive and result.findings:
            to_verify = [f for f in result.findings if f.exploit_status != "succeeded" and f.category != Category.RECON]
            if to_verify:
                vstats = await run_verification_phase(ctx, to_verify, emit)
                result.stats["fp_verified"] = vstats.get("verified", 0)
                result.stats["fp_flagged"] = vstats.get("flagged", 0)

        # Code-location evidence: pin every finding to the vulnerable sink
        # (source mapping when --source-dir is given, inferred sink pattern
        # otherwise) so the report shows WHERE in the code the bug lives.
        mapped = map_all_findings(result, emit)
        if mapped:
            result.stats["code_mapped"] = mapped

        if config.use_external_tools:
            await _run_external(config, ctx, result, emit, scope)
    except _LabDiedError:
        # The death guard already emitted the expired-lab banner and
        # recorded the error on the result; unwind cleanly so the
        # report/console summary still gets written.
        pass
    finally:
        await client.aclose()

    result.finished_at = datetime.now(timezone.utc)
    result.stats["findings"] = len(result.findings)
    result.stats["exploited"] = sum(1 for f in result.findings if f.exploit_status == "succeeded")
    if client.throttle_events:
        result.stats["throttle_events"] = client.throttle_events
        emit(
            f"Note: the target rate-limited the scan {client.throttle_events} time(s) "
            "(adaptive back-off applied). If results look starved, re-run on a "
            "fresh instance with lower --concurrency."
        )
    # Objective follow-up: when a training lab stayed open, tell the operator
    # exactly what to do next instead of leaving a bare "not solved".
    obj = result.objective or {}
    lab_dead = bool(result.stats.get("lab_dead"))
    if lab_dead:
        # The expired-lab banner was already printed by the probe or a death
        # guard; only add the ONE missing pointer (verify before re-running).
        emit("")
        emit("  Run  python -m bughound check '<URL>'  any time for an instant")
        emit("  alive/dead verdict -- 10x faster than a full scan.")
        emit("")
    elif obj.get("type") == "portswigger-lab" and obj.get("solved_after") is not True:
        emit("")
        emit("  ============================================================")
        emit("  LAB OBJECTIVE REMAINS OPEN")
        if obj.get("title"):
            emit(f"  Lab: {obj['title']}")
        emit("  Next steps:")
        emit("   1. Confirm the instance is FRESH (Academy labs expire fast;")
        emit("      an expired instance can never be solved -- restart it).")
        emit("      Verify instantly:  python -m bughound check '<URL>'")
        emit("   2. Re-run with --aggressive --i-am-authorized (the exploit/")
        emit("      solve phase is disabled in safe/detection-only mode).")
        emit("   3. If throttling was reported above, wait a few minutes and")
        emit("      re-run on a fresh instance (the lab rate-limits bots).")
        emit("   4. Increase --solve-budget for budget-exhausted runs.")
        emit("  ============================================================")
        emit("")
    return result


def _register_direct_targets(config: ScanConfig, ctx: ScanContext, result: ScanResult, emit) -> None:
    """Register --exploit-endpoint URLs as request targets + seed findings."""
    from urllib.parse import parse_qsl, urlparse

    for ep in config.exploit_endpoints:
        # Resolve bare paths ("/product/stock", "product/stock") against the
        # scan target so the direct target always carries scheme + host.
        # Previously "http://" + "/product/stock" produced the hostless URL
        # "http:///product/stock", whose every request fails silently (the
        # HTTP client maps invalid URLs to a status-0 response) and the whole
        # exploit chain quietly did nothing.
        if "://" in ep:
            parsed_ep = urlparse(ep)
        else:
            tgt = urlparse(config.target_url)
            path = ep if ep.startswith("/") else f"/{ep}"
            parsed_ep = urlparse(f"{tgt.scheme or 'http'}://{tgt.netloc}{path}")
        base = f"{parsed_ep.scheme}://{parsed_ep.netloc}{parsed_ep.path or '/'}"
        qs = dict(parse_qsl(parsed_ep.query))

        if config.exploit_body:
            # Raw-body mode (XML/JSON endpoints behind input filters): the
            # body template carries the {INJ} marker; payloads are substituted
            # there and optionally entity-encoded to bypass the filter.
            param = config.exploit_param or "INJ"
            base_value = qs.get(param, "1")  # numeric default fits lab-style ids
            rt = RequestTarget(
                url=base,
                method=(config.exploit_method or "POST").upper(),
                params={"INJ": base_value},
                source="direct",
                body_template=config.exploit_body,
                content_type=config.exploit_content_type
                or ("application/xml" if config.exploit_body.lstrip().startswith("<") else ""),
                encoding=config.exploit_encode or "",
            )
            ctx.request_targets = [t for t in ctx.request_targets if t.url != base] + [rt]
            finding = Finding(
                category=Category.SQLI,
                title=f"Direct-exploit target: injection surface in '{param}' (raw body)",
                severity=Severity.CRITICAL,
                confidence="firm",
                url=base,
                description=(
                    f"Operator-designated exploitation target: the raw-body parameter '{param}' "
                    f"on {base} (body template with {{INJ}} marker"
                    + (f", '{config.exploit_encode}' encoding" if config.exploit_encode else "")
                    + ") is worked through the full exploit chain (UNION extraction, "
                    "tautology reveal, boolean-blind extraction + credential login)."
                ),
                evidence=(
                    "designated by the operator via --exploit-endpoint --exploit-body; "
                    "exploit chain attempts logged below"
                ),
                request=f"{rt.method} {base} (body: {config.exploit_body} with {{INJ}}=<payload>)",
                remediation="Use parameterized queries / prepared statements; never build SQL from input.",
                cwe="CWE-89",
                module="direct-exploit",
                verified=False,
            )
            result.add(finding)
            emit(
                f"  [direct] registered raw-body exploitation target: {base} "
                f"(encode={config.exploit_encode or 'none'})"
            )
            continue

        param = config.exploit_param or (next(iter(qs), None))
        params = qs or ({param: "test"} if param else {})
        if not param:
            emit(f"  [direct] {ep}: no parameter given (use --exploit-param); skipping")
            continue
        rt = RequestTarget(
            url=base,
            method=(config.exploit_method or "GET").upper(),
            params=params,
            source="direct",
        )
        # Replace any duplicate discovered target for the same path.
        ctx.request_targets = [t for t in ctx.request_targets if t.url != base] + [rt]
        finding = Finding(
            category=Category.SQLI,
            title=f"Direct-exploit target: injection surface in '{param}'",
            severity=Severity.CRITICAL,
            confidence="firm",
            url=base,
            description=(
                f"Operator-designated exploitation target: parameter '{param}' on {base} "
                "is worked through the full exploit chain (UNION extraction, tautology "
                "reveal, boolean-blind extraction + credential login)."
            ),
            evidence="designated by the operator via --exploit-endpoint; exploit chain attempts logged below",
            request=f"{rt.method} {base} ({param}=<payload>)",
            remediation="Use parameterized queries / prepared statements; never build SQL from input.",
            cwe="CWE-89",
            module="direct-exploit",
            verified=False,
        )
        result.add(finding)
        emit(f"  [direct] registered exploitation target: {base} (param '{param}')")


async def _run_external(config, ctx, result, emit, scope) -> None:
    if scope.url_denied(config.target_url):
        result.errors.append("External tools skipped: target is on the denylist.")
        return
    host = integrations.host_from_url(config.target_url)
    missing = integrations.missing_tools_note()
    if missing:
        result.errors.append(f"External tools not installed (skipped): {', '.join(missing)}")

    tasks = [integrations.run_nuclei(config.target_url)]
    if config.aggressive:
        if not scope.host_denied(host):
            tasks.append(integrations.run_nmap(host))
        for rt in ctx.request_targets[:3]:
            if not scope.url_denied(rt.url):
                tasks.append(integrations.run_sqlmap(rt.url, rt.method, rt.params))
    emit("Running external tools (nuclei/nmap/sqlmap where available)...")
    for group in await asyncio.gather(*tasks, return_exceptions=True):
        if isinstance(group, Exception):
            result.errors.append(f"external tool error: {group}")
            continue
        for f in group:
            result.add(f)
            if f.module not in result.modules_run:
                result.modules_run.append(f.module)
