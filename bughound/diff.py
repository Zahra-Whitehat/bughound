"""Report diffing -- Sn1per-style continuous attack-surface monitoring.

Sn1per's ASM story is "diff yesterday's surface against today's so new
exposures hit your SOC within hours". ``bughound diff old.json new.json``
brings the same workflow to bughound reports: point it at two saved JSON
reports for the same host and it reports what changed --

- **new findings** (were not present in the baseline report),
- **resolved findings** (present in the baseline, gone now),
- **exploit-status changes** (a candidate that is now exploited),
- **attack-surface changes**: new/removed subdomains, tech-stack entries,
  admin paths, API docs, backup files and source maps.

The diff is *evidence-preserving*: every row carries the finding's
fingerprint so the operator can grep both reports for the exact item.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field


def _fingerprint(entry: dict) -> str:
    """Recompute the finding fingerprint from a serialized report entry.

    Mirrors ``Finding.fingerprint`` (``category.name|url|title``).
    """
    category = entry.get("category", "")
    url = entry.get("url", "")
    title = entry.get("title", "")
    raw = f"{category}|{url}|{title}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class DiffResult:
    """Everything that changed between two reports."""

    old_path: str = ""
    new_path: str = ""
    host: str = ""
    new_findings: list[dict] = field(default_factory=list)
    resolved_findings: list[dict] = field(default_factory=list)
    now_exploited: list[dict] = field(default_factory=list)
    recon_added: dict[str, list] = field(default_factory=dict)
    recon_removed: dict[str, list] = field(default_factory=dict)
    #: keys of recon lists that were compared
    recon_keys: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(
            self.new_findings
            or self.resolved_findings
            or self.now_exploited
            or self.recon_added
            or self.recon_removed
        )


#: Recon keys worth monitoring (aligned with modules.base.RECON_KEYS).
WATCHED_RECON_KEYS: list[str] = [
    "subdomains",
    "admin_paths",
    "api_docs",
    "backup_files",
    "sourcemaps",
    "js_endpoints",
    "emails",
]


def load_report(path: str) -> dict:
    with open(path) as fh:
        return json.load(fh)


def diff_reports(old: dict, new: dict) -> DiffResult:
    """Diff two serialized :class:`ScanResult` dicts."""
    old_findings = {_fingerprint(f): f for f in old.get("findings", [])}
    new_findings = {_fingerprint(f): f for f in new.get("findings", [])}
    old_fp = set(old_findings)
    new_fp = set(new_findings)

    out = DiffResult()
    out.host = (new.get("target") or {}).get("host", "")

    for fp in new_fp - old_fp:
        out.new_findings.append(new_findings[fp])
    for fp in old_fp - new_fp:
        out.resolved_findings.append(old_findings[fp])
    for fp in old_fp & new_fp:
        old_exp = old_findings[fp].get("exploit_status")
        new_exp = new_findings[fp].get("exploit_status")
        if old_exp != "succeeded" and new_exp == "succeeded":
            out.now_exploited.append(new_findings[fp])

    old_recon = old.get("recon") or {}
    new_recon = new.get("recon") or {}
    for key in WATCHED_RECON_KEYS:
        old_items = {str(i) for i in (old_recon.get(key) or []) if i}
        new_items = {str(i) for i in (new_recon.get(key) or []) if i}
        added = sorted(new_items - old_items)
        removed = sorted(old_items - new_items)
        if added:
            out.recon_added[key] = added
        if removed:
            out.recon_removed[key] = removed
    return out


def diff_files(old_path: str, new_path: str) -> DiffResult:
    """Load two report files and diff them."""
    return diff_reports(load_report(old_path), load_report(new_path))


def diff_markdown(d: DiffResult, old_path: str = "", new_path: str = "") -> str:
    """Render a :class:`DiffResult` as a Markdown change report."""
    lines: list[str] = ["# Attack-surface diff", ""]
    if d.host:
        lines.append(f"- **Host:** {d.host}")
    if old_path and new_path:
        lines.append(f"- **Baseline:** `{old_path}`")
        lines.append(f"- **Current:** `{new_path}`")
    lines.append("")

    if not d.has_changes:
        lines.append("No changes detected between the two reports.")
        return "\n".join(lines) + "\n"

    if d.new_findings:
        lines.extend([f"## New findings ({len(d.new_findings)})", ""])
        for f in d.new_findings:
            lines.append(
                f"- **[{str(f.get('severity', '?')).upper()}]** {f.get('title', '?')} "
                f"-- `{f.get('url', '?')}` (fingerprint `{_fingerprint(f)}`)"
            )
        lines.append("")
    if d.resolved_findings:
        lines.extend([f"## Resolved findings ({len(d.resolved_findings)})", ""])
        for f in d.resolved_findings:
            lines.append(
                f"- {f.get('title', '?')} -- `{f.get('url', '?')}` (fingerprint `{_fingerprint(f)}`)"
            )
        lines.append("")
    if d.now_exploited:
        lines.extend([f"## Newly exploited ({len(d.now_exploited)})", ""])
        for f in d.now_exploited:
            lines.append(f"- \u2713 {f.get('title', '?')} -- impact proven by the exploit phase")
        lines.append("")

    if d.recon_added:
        lines.append("## Attack-surface additions", "")
        for key, items in d.recon_added.items():
            lines.append(f"- **{key}:** {', '.join(items[:20])}"
                         + (f" (+{len(items) - 20} more)" if len(items) > 20 else ""))
        lines.append("")
    if d.recon_removed:
        lines.append("## Attack-surface removals", "")
        for key, items in d.recon_removed.items():
            lines.append(f"- **{key}:** {', '.join(items[:20])}"
                         + (f" (+{len(items) - 20} more)" if len(items) > 20 else ""))
        lines.append("")
    return "\n".join(lines) + "\n"
