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
    lines.append(f"- **URLs crawled:** {result.stats.get('urls_crawled', 0)}")
    lines.append(f"- **Injectable targets:** {result.stats.get('injectable_targets', 0)}")
    lines.append("")

    counts = Counter(f.severity for f in result.findings)
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in SEVERITY_ORDER:
        lines.append(f"| {_severity_badge(sev)} | {counts.get(sev, 0)} |")
    lines.append(f"| **Total** | **{len(result.findings)}** |")
    lines.append("")

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
        lines.append(f"### {i}. [{_severity_badge(f.severity)}] {f.title}")
        lines.append("")
        lines.append(f"- **Class:** {f.category.value}")
        lines.append(f"- **URL:** {f.url}")
        lines.append(f"- **Status:** {status}")
        if f.cwe:
            lines.append(f"- **CWE:** {f.cwe}")
        lines.append(f"- **Module:** {f.module}")
        lines.append("")
        if f.description:
            lines.append(f"**Description.** {f.description}")
            lines.append("")
        if f.evidence:
            lines.append("**Evidence (proof).**")
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
        if f.remediation:
            lines.append(f"**Remediation.** {f.remediation}")
            lines.append("")
        if f.references:
            lines.append("**References.** " + ", ".join(f.references))
            lines.append("")

    return "\n".join(lines)


def category_summary(result: ScanResult) -> dict[str, int]:
    c: Counter[str] = Counter()
    for f in result.findings:
        c[f.category.value] += 1
    return dict(c)


ALL_CATEGORIES = [c.value for c in Category]
