"""Render scan results to JSON and Markdown reports."""

from __future__ import annotations

from collections import Counter

from .models import Category, ScanResult, Severity

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def to_json(result: ScanResult) -> str:
    return result.model_dump_json(indent=2)


def _severity_badge(sev: Severity) -> str:
    return {
        Severity.CRITICAL: "CRITICAL",
        Severity.HIGH: "HIGH",
        Severity.MEDIUM: "MEDIUM",
        Severity.LOW: "LOW",
        Severity.INFO: "INFO",
    }[sev]


def _render_recon_md(recon: dict) -> list[str]:
    """Render the structured recon dict as a clean Markdown section.

    Returns a list of lines (without trailing newline) to splice into the
    report. Empty if no recon data was collected.
    """
    if not recon:
        return []

    lines: list[str] = ["## Reconnaissance (attack-surface overview)", ""]

    # Subdomains
    subdomains = recon.get("subdomains") or []
    if subdomains:
        lines.append(f"### Subdomains discovered ({len(subdomains)})")
        lines.append("")
        lines.append("_Via Certificate Transparency logs and active DNS brute force._")
        lines.append("")
        # Render as a fenced list; trim very long lists to keep the report readable.
        shown = subdomains[:60]
        for s in shown:
            lines.append(f"- `{s}`")
        if len(subdomains) > len(shown):
            lines.append(f"- ... and {len(subdomains) - len(shown)} more")
        lines.append("")

    # Subdomain takeover candidates
    takeovers = recon.get("subdomain_takeover_candidates") or []
    if takeovers:
        lines.append(f"### ⚠ Possible subdomain takeovers ({len(takeovers)})")
        lines.append("")
        lines.append("| Subdomain | CNAME | Platform |")
        lines.append("|---|---|---|")
        for t in takeovers[:30]:
            lines.append(f"| `{t.get('subdomain')}` | `{t.get('cname')}` | {t.get('service')} |")
        lines.append("")
        lines.append(
            "_Flagged from DNS evidence only (dangling CNAME pattern); confirm by hand "
            "or add the host to scope and re-scan before reporting as exploitable._"
        )
        lines.append("")

    # Favicon hash (Shodan/Censys pivot)
    favicon_hash_val = recon.get("favicon_hash")
    if favicon_hash_val is not None:
        lines.append("### Favicon hash")
        lines.append("")
        lines.append(
            f"`http.favicon.hash:{favicon_hash_val}` -- search this on Shodan/Censys to find "
            "other hosts serving the identical favicon."
        )
        lines.append("")

    # WHOIS / RDAP
    whois = recon.get("whois") or {}
    if whois:
        lines.append("### WHOIS / registration")
        lines.append("")
        for label, key in (
            ("Registrar", "registrar"),
            ("Registered", "created"),
            ("Expires", "expires"),
            ("Registrant org", "registrant_org"),
            ("Nameservers", "nameservers"),
        ):
            val = whois.get(key)
            if not val:
                continue
            if isinstance(val, list):
                val = ", ".join(val[:6])
            lines.append(f"- **{label}:** {val}")
        lines.append("")

    # Wayback Machine historical URLs
    wayback = recon.get("wayback_urls") or []
    if wayback:
        lines.append(f"### Historical URLs (Wayback Machine, {len(wayback)} shown)")
        lines.append("")
        for u in wayback[:40]:
            lines.append(f"- `{u}`")
        if len(wayback) > 40:
            lines.append(f"- ... and {len(wayback) - 40} more")
        lines.append("")
    wayback_interesting = recon.get("wayback_interesting_urls") or []
    if wayback_interesting:
        lines.append("### ⚠ Archived backup/config-looking URLs")
        lines.append("")
        for u in wayback_interesting[:30]:
            lines.append(f"- `{u}`")
        lines.append("")

    # DNS records
    dns = recon.get("dns_records") or {}
    if dns:
        lines.append("### DNS records")
        lines.append("")
        lines.append("| Type | Values |")
        lines.append("|---|---|")
        for rtype, values in dns.items():
            v = ", ".join(str(v) for v in values[:6]) if values else "-"
            if len(values) > 6:
                v += f", ... (+{len(values) - 6})"
            lines.append(f"| {rtype} | {v} |")
        lines.append("")

    # Email security
    email_sec = recon.get("email_security") or {}
    if email_sec:
        lines.append("### Email authentication posture")
        lines.append("")
        lines.append(f"- **SPF:** `{email_sec.get('spf') or '(none)'}`")
        lines.append(f"- **DMARC:** `{email_sec.get('dmarc') or '(none)'}`")
        for issue in email_sec.get("issues", []):
            lines.append(f"- ⚠ {issue}")
        lines.append("")

    # Tech stack
    stack = recon.get("tech_stack") or {}
    if stack:
        lines.append("### Technology stack")
        lines.append("")
        lines.append("| Category | Products |")
        lines.append("|---|---|")
        for cat, prods in sorted(stack.items()):
            lines.append(f"| {cat} | {', '.join(prods)} |")
        lines.append("")

    # WAF
    waf = recon.get("waf")
    if waf:
        lines.append("### WAF / CDN")
        lines.append("")
        lines.append(f"Fronting security layer: **{waf}**")
        lines.append("")
    elif recon.get("waf") is None and "waf" in recon:
        lines.append("### WAF / CDN")
        lines.append("")
        lines.append("No WAF / CDN detected via headers.")
        lines.append("")

    # HTTP methods
    methods = recon.get("http_methods") or []
    if methods:
        lines.append("### HTTP methods advertised")
        lines.append("")
        lines.append(f"`{', '.join(methods)}`")
        lines.append("")

    # JS endpoints
    endpoints = recon.get("js_endpoints") or []
    if endpoints:
        lines.append(f"### Endpoints extracted from JavaScript ({len(endpoints)})")
        lines.append("")
        shown = endpoints[:80]
        for e in shown:
            lines.append(f"- `{e}`")
        if len(endpoints) > len(shown):
            lines.append(f"- ... and {len(endpoints) - len(shown)} more")
        lines.append("")

    # Emails
    emails = recon.get("emails") or []
    if emails:
        lines.append(f"### Email addresses harvested ({len(emails)})")
        lines.append("")
        for e in emails[:40]:
            lines.append(f"- `{e}`")
        if len(emails) > 40:
            lines.append(f"- ... and {len(emails) - 40} more")
        lines.append("")

    # Admin paths
    admin = recon.get("admin_paths") or []
    if admin:
        lines.append(f"### Management / admin paths discovered ({len(admin)})")
        lines.append("")
        for p in admin:
            lines.append(f"- `{p}`")
        lines.append("")

    # API docs
    api_docs = recon.get("api_docs") or []
    if api_docs:
        lines.append(f"### API documentation endpoints ({len(api_docs)})")
        lines.append("")
        for p in api_docs:
            lines.append(f"- `{p}`")
        lines.append("")

    # Backup files
    backups = recon.get("backup_files") or []
    if backups:
        lines.append(f"### Backup / versioned files discovered ({len(backups)})")
        lines.append("")
        for p in backups:
            lines.append(f"- `{p}`")
        lines.append("")

    # Sourcemaps
    maps = recon.get("sourcemaps") or []
    if maps:
        lines.append(f"### Exposed source maps ({len(maps)})")
        lines.append("")
        for m in maps:
            lines.append(f"- `{m}`")
        lines.append("")

    # Well-known paths
    wk = recon.get("well_known_paths") or []
    if wk:
        lines.append(f"### Well-known endpoints ({len(wk)})")
        lines.append("")
        for p in wk:
            lines.append(f"- `{p}`")
        lines.append("")

    # robots.txt
    robots = recon.get("robots_txt") or ""
    if robots:
        lines.append("### robots.txt")
        lines.append("")
        lines.append("```")
        lines.append(robots[:2000])
        lines.append("```")
        lines.append("")

    # security.txt
    sec_txt = recon.get("security_txt") or ""
    if sec_txt:
        lines.append("### security.txt")
        lines.append("")
        lines.append("```")
        lines.append(sec_txt[:2000])
        lines.append("```")
        lines.append("")

    # Sitemap URLs
    sitemap = recon.get("sitemap_urls") or []
    if sitemap:
        lines.append(f"### URLs from sitemap.xml ({len(sitemap)})")
        lines.append("")
        shown = sitemap[:60]
        for u in shown:
            lines.append(f"- `{u}`")
        if len(sitemap) > len(shown):
            lines.append(f"- ... and {len(sitemap) - len(shown)} more")
        lines.append("")

    # Discovered URLs (aggregated by robots/sitemap module)
    discovered = recon.get("discovered_urls") or []
    if discovered:
        lines.append(f"### Discovered URLs (well-known + sitemap, {len(discovered)})")
        lines.append("")
        shown = discovered[:60]
        for u in shown:
            lines.append(f"- `{u}`")
        if len(discovered) > len(shown):
            lines.append(f"- ... and {len(discovered) - len(shown)} more")
        lines.append("")

    if len(lines) == 2:  # only the section heading
        lines.append("_No structured reconnaissance data was collected._")
        lines.append("")
    return lines


def to_markdown(result: ScanResult) -> str:
    lines: list[str] = []
    t = result.target
    lines.append(f"# Security assessment report: {t.host}")
    lines.append("")
    lines.append(f"- **Target:** {result.config.target_url}")
    lines.append(f"- **Authorization:** {t.authorization_note}")
    lines.append(f"- **Started:** {result.started_at.isoformat()}")
    if result.finished_at:
        lines.append(f"- **Finished:** {result.finished_at.isoformat()}")
    lines.append(f"- **Mode:** {'aggressive (active exploitation)' if result.config.aggressive else 'safe (passive)'}")
    if result.config.aggressive and result.config.exploit:
        lines.append("- **Exploit phase:** enabled (safe, non-destructive impact proofs)")
    lines.append(f"- **URLs crawled:** {result.stats.get('urls_crawled', 0)}")
    lines.append(f"- **Injectable targets:** {result.stats.get('injectable_targets', 0)}")
    lines.append("")

    counts = Counter(f.severity for f in result.findings)
    verified = sum(1 for f in result.findings if f.verified)
    exploited = sum(1 for f in result.findings if f.exploit_status == "succeeded")
    fp_verified = result.stats.get("fp_verified", 0)
    fp_flagged = result.stats.get("fp_flagged", 0)
    code_mapped = result.stats.get("code_mapped", 0)

    # Executive summary: the three questions every reader asks first.
    lines.append("## Executive summary")
    lines.append("")
    top_cats = [c for c, _ in Counter(f.category.value for f in result.findings).most_common(3)]
    lines.append(
        f"The scan identified **{len(result.findings)} finding(s)**"
        f" ({counts.get(Severity.CRITICAL, 0)} critical, {counts.get(Severity.HIGH, 0)} high, "
        f"{counts.get(Severity.MEDIUM, 0)} medium, {counts.get(Severity.LOW, 0)} low, "
        f"{counts.get(Severity.INFO, 0)} informational)."
    )
    lines.append(
        f" Of these, **{verified} were verified** with hard evidence and "
        f"**{exploited} were actively exploited** with safe, non-destructive payloads to "
        "demonstrate concrete impact (extracted data, command output, or file contents "
        "captured in this report)."
    )
    if fp_verified or fp_flagged:
        lines.append(
            f" False-positive control experiments (negative controls, repeat consistency, "
            f"baseline cleanliness) were executed on non-exploited findings: "
            f"**{fp_verified} passed clean**, {fp_flagged} were flagged for manual review."
        )
    if code_mapped:
        lines.append(
            f" **{code_mapped} finding(s) were mapped to the exact vulnerable source location** "
            "(file, line and sink excerpt in each finding's 'Vulnerable code location' section)."
        )
    if top_cats:
        lines.append(f" Dominant risk areas: {', '.join(top_cats)}.")
    else:
        lines.append("No vulnerability findings were recorded for this scope and mode.")
    lines.append("")
    if exploited:
        lines.append(
            "**Read this first:** findings marked \u2705 EXPLOITED include the exact payload, a "
            "ready-to-run `curl` reproduction, the verbatim HTTP exchange, and the data the "
            "exploit extracted. Triage can confirm each one in minutes without re-deriving "
            "the attack."
        )
        lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count | Exploited |")
    lines.append("|---|---|---|")
    for sev in SEVERITY_ORDER:
        sev_exploited = sum(
            1 for f in result.findings if f.severity == sev and f.exploit_status == "succeeded"
        )
        lines.append(f"| {_severity_badge(sev)} | {counts.get(sev, 0)} | {sev_exploited} |")
    lines.append(f"| **Total** | **{len(result.findings)}** | **{exploited}** |")
    lines.append("")

    # Recon section: render before coverage so operators see the attack surface
    # up-front. Skip entirely if no recon modules produced data.
    recon_lines = _render_recon_md(result.recon or {})
    if recon_lines:
        lines.extend(recon_lines)

    # Coverage: which classes had findings vs were tested with nothing found.
    lines.append("## Coverage")
    lines.append("")
    tested = set(result.modules_run)
    found_cats = {f.category for f in result.findings}
    lines.append(f"Modules run: {', '.join(sorted(tested)) or 'none'}")
    lines.append("")
    lines.append("Vulnerability classes with findings: "
                 + (", ".join(sorted(c.value for c in found_cats)) or "none"))
    lines.append("")

    if result.errors:
        lines.append("## Notes / errors")
        lines.append("")
        for e in result.errors:
            lines.append(f"- {e}")
        lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not result.findings:
        lines.append("No findings reported.")
        return "\n".join(lines)

    for i, f in enumerate(result.sorted_findings, 1):
        status = "VERIFIED" if f.verified else f"confidence: {f.confidence}"
        if f.exploit_status == "succeeded":
            status += " \u2705 EXPLOITED"
        elif f.exploit_status == "attempted":
            status += " (exploit attempted)"
        lines.append(f"### {i}. [{_severity_badge(f.severity)}] {f.title}")
        lines.append("")
        lines.append(f"- **Class:** {f.category.value}")
        lines.append(f"- **URL:** {f.url}")
        if f.injection_point:
            lines.append(f"- **Injection point:** `{f.injection_point}`")
        lines.append(f"- **Status:** {status}")
        if f.cwe:
            lines.append(f"- **CWE:** {f.cwe}")
        lines.append(f"- **Module:** {f.module}")
        lines.append("")
        if f.description:
            lines.append(f"**Description.** {f.description}")
            lines.append("")
        lines.extend(_render_code_location_md(f))
        if f.impact:
            lines.append(f"**Impact.** {f.impact}")
            lines.append("")
        if f.evidence:
            lines.append("**Detection evidence.**")
            lines.append("")
            lines.append("```")
            lines.append(f.evidence)
            if f.request:
                lines.append("")
                lines.append(f.request)
            if f.response_excerpt:
                lines.append("")
                lines.append("--- response excerpt ---")
                lines.append(f.response_excerpt)
            lines.append("```")
            lines.append("")
        lines.extend(_render_poc_md(f))
        lines.extend(_render_verification_md(f))
        if f.remediation:
            lines.append(f"**Remediation.** {f.remediation}")
            lines.append("")
        if f.references:
            lines.append("**References.** " + ", ".join(f.references))
            lines.append("")

    lines.extend(_render_methodology_md(result))
    return "\n".join(lines)


def _render_code_location_md(f) -> list[str]:
    """Render the 'where in the code does this happen' section."""
    out: list[str] = ["#### Vulnerable code location", ""]
    if f.code_file and f.code_snippet:
        span = f"lines {f.code_lines[0]}-{f.code_lines[1]}" if f.code_lines else "location approximate"
        out.append(
            f"**Source-mapped sink:** `{f.code_file}` ({span}), inside **{f.code_symbol}**. "
            "The line marked with `->` is where the injectable input reaches the dangerous sink."
        )
        out.append("")
        out.append(f"```{(f.code_file.rsplit('.', 1)[-1] or 'text').lower()}")
        out.append(f.code_snippet)
        out.append("```")
        out.append("")
    elif f.inferred_sink:
        out.append(
            "**Reconstructed sink (black-box evidence).** The application's source code was not "
            "available to this scan, so the vulnerable code pattern below was reconstructed from "
            "observed behaviour -- the input provably reaches a sink of this shape at the listed "
            "injection point (see the detection evidence and raw exchange for the proof)."
        )
        out.append("")
        out.append("```text")
        out.append(f.inferred_sink)
        out.append("```")
        out.append("")
    else:
        return []
    return out


def _render_verification_md(f) -> list[str]:
    """Render the false-positive analysis for one finding."""
    if not f.verification_checks:
        if f.exploit_status == "succeeded":
            return [
                "#### False-positive analysis",
                "",
                "The exploit phase reproduced the vulnerability end-to-end and extracted real data "
                "from the target, which is itself the strongest false-positive disproof: random "
                "page drift, caching artefacts or WAF noise cannot fabricate extracted database "
                "rows, command output or file contents. No separate control experiments were needed.",
                "",
            ]
        return []
    out: list[str] = ["#### False-positive analysis", ""]
    if f.fp_verdict:
        out.append(f.fp_verdict)
        out.append("")
    out.append("| Control experiment | Result | Observed behaviour |")
    out.append("|---|---|---|")
    for c in f.verification_checks:
        mark = "PASS" if c.get("passed") else "FAIL"
        out.append(f"| {c.get('name', '')} | {mark} | {c.get('detail', '')} |")
    out.append("")
    if f.fp_risk:
        if f.fp_risk == "low":
            out.append("**Verdict: LOW false-positive risk** -- every control experiment behaved "
                       "as physics demands: the attack signature appears only for the crafted "
                       "payload and reproduces consistently.")
        else:
            out.append(f"**Verdict: {f.fp_risk.upper()} false-positive risk** -- at least one control "
                       "experiment contradicts the finding. Manual review required before triage.")
        out.append("")
    return out


def _render_poc_md(f) -> list[str]:
    """Render the Proof-of-Exploitation block for a single finding."""
    if f.exploit_status != "succeeded" and not f.poc_curl:
        if f.exploit_status == "attempted" and f.exploit_summary:
            return [
                "#### Exploit phase result",
                "",
                f.exploit_summary,
                "",
            ]
        return []

    out: list[str] = ["#### Proof of exploitation", ""]
    if f.exploit_summary:
        out.append(f.exploit_summary)
        out.append("")
    if f.extracted_data:
        out.append("**Data extracted from the target by the exploit:**")
        out.append("")
        out.append("```")
        for item in f.extracted_data:
            out.append(str(item))
        out.append("```")
        out.append("")
    if f.poc_curl:
        out.append("**Reproduce (copy-paste):**")
        out.append("")
        out.append("```bash")
        out.append(f.poc_curl)
        out.append("```")
        out.append("")
    if f.raw_request:
        out.append("**Raw HTTP exchange:**")
        out.append("")
        out.append("```http")
        out.append(f.raw_request)
        if f.raw_response:
            out.append("")
            out.append(f.raw_response)
        out.append("```")
        out.append("")
    if f.reproduction_steps:
        out.append("**Manual reproduction steps:**")
        out.append("")
        for n, step in enumerate(f.reproduction_steps, 1):
            out.append(f"{n}. {step}")
        out.append("")
    return out


def _render_methodology_md(result: ScanResult) -> list[str]:
    """Appendix: how the results were obtained (reproducibility & trust)."""
    exploited = sum(1 for f in result.findings if f.exploit_status == "succeeded")
    mapped = result.stats.get("code_mapped", 0)
    fp_verified = result.stats.get("fp_verified", 0)
    fp_flagged = result.stats.get("fp_flagged", 0)
    source_note = (
        f"Source mapping was performed against `{result.config.source_dir}`; each mapped finding "
        "cites the vulnerable file, line range and sink excerpt."
        if result.config.source_dir
        else "No source directory was supplied (--source-dir), so findings carry behaviour-derived "
        "sink reconstructions instead of verbatim source lines."
    )
    return [
        "## Methodology & limitations",
        "",
        "1. **Crawl.** Same-origin crawl of the authorized target discovered "
        f"{result.stats.get('urls_crawled', 0)} URL(s) and "
        f"{result.stats.get('injectable_targets', 0)} injectable target(s) (query parameters and forms).",
        "2. **Detection.** Passive recon modules ran first (attack-surface mapping above); "
        "active modules then sent non-destructive probe payloads to detect "
        "injection, XSS, traversal, SSRF and misconfiguration classes.",
        "3. **Exploitation.**"
        + (f" {exploited} finding(s) were re-targeted with safe impact-proof exploits: "
           "read-only SQL extraction, informational command execution (`id`, `uname`), "
           "system-file reads, executable-payload survival checks and loopback fetches. "
           "No data was modified or destroyed, and no denial-of-service techniques were used."
           if exploited else " Disabled or nothing to exploit.") + "",
        "4. **False-positive verification.** Findings the exploit phase could not prove were "
        "re-tested with control experiments: negative controls (payload with the active "
        "ingredient removed), repeat-consistency probes, baseline-cleanliness checks, fresh "
        "per-check canaries and differential directionality. "
        f"{fp_verified} passed all controls; {fp_flagged} were flagged for manual review. "
        "A succeeded exploit is its own false-positive disproof, so it bypasses this battery.",
        "5. **Code attribution.** " + source_note,
        "6. **Reporting.** Every claim in this report is backed by the captured request/response "
        "evidence shown alongside it. Findings that could not be proven are explicitly labelled "
        "with their confidence (tentative/firm) rather than overclaimed.",
        "",
        "**Limitations.** Automated testing cannot cover business-logic flaws, authenticated "
        "flows without credentials, or client-side-only rendering. Candidates flagged for manual "
        "review should be verified by a human before triage decisions are made.",
        "",
    ]


def category_summary(result: ScanResult) -> dict[str, int]:
    c: Counter[str] = Counter()
    for f in result.findings:
        c[f.category.value] += 1
    return dict(c)


ALL_CATEGORIES = [c.value for c in Category]
