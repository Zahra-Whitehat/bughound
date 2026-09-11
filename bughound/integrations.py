"""Wrappers around external security tools (nuclei, nmap, sqlmap).

Each wrapper degrades gracefully: if the binary is not installed the wrapper
returns an informational note instead of failing the scan.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from urllib.parse import urlencode, urlparse

from .models import Category, Finding, Severity

SEVERITY_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "unknown": Severity.INFO,
}


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


async def _run(cmd: list[str], timeout: float) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return -1, "", f"timed out after {timeout}s"
    return proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace")


async def run_nuclei(base_url: str, timeout: float = 600) -> list[Finding]:
    if not tool_available("nuclei"):
        return []
    cmd = ["nuclei", "-u", base_url, "-jsonl", "-silent", "-timeout", "10"]
    code, out, _ = await _run(cmd, timeout)
    findings: list[Finding] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = j.get("info", {})
        sev = SEVERITY_MAP.get(str(info.get("severity", "info")).lower(), Severity.INFO)
        findings.append(
            Finding(
                category=Category.MISCONFIG,
                title=f"[nuclei] {info.get('name', j.get('template-id', 'finding'))}",
                severity=sev,
                confidence="firm",
                url=j.get("matched-at") or j.get("host") or base_url,
                description=info.get("description", "") or "Reported by a nuclei template.",
                evidence=f"template-id={j.get('template-id')} matcher={j.get('matcher-name', '')}",
                remediation=(info.get("remediation") or "See the nuclei template reference."),
                references=info.get("reference", []) or [],
                module="nuclei",
                verified=True,
            )
        )
    return findings


async def run_nmap(host: str, timeout: float = 300) -> list[Finding]:
    if not tool_available("nmap"):
        return []
    cmd = ["nmap", "-Pn", "-T4", "--top-ports", "200", "-sV", host]
    code, out, _ = await _run(cmd, timeout)
    findings: list[Finding] = []
    risky = {"21": "FTP", "23": "Telnet", "3306": "MySQL", "5432": "Postgres", "6379": "Redis",
             "27017": "MongoDB", "9200": "Elasticsearch", "5900": "VNC", "3389": "RDP", "2375": "Docker API"}
    for line in out.splitlines():
        line = line.strip()
        if "/tcp" in line and "open" in line:
            port = line.split("/")[0]
            if port in risky:
                findings.append(
                    Finding(
                        category=Category.MISCONFIG,
                        title=f"Sensitive service exposed: {risky[port]} (port {port})",
                        severity=Severity.MEDIUM,
                        confidence="firm",
                        url=f"{host}:{port}",
                        description=f"nmap found {risky[port]} exposed on port {port}.",
                        evidence=line,
                        remediation="Restrict the service via firewall/VPN; do not expose datastores/admin ports publicly.",
                        module="nmap",
                        verified=True,
                    )
                )
    return findings


async def run_sqlmap(url: str, method: str, params: dict[str, str], timeout: float = 300) -> list[Finding]:
    if not tool_available("sqlmap") or not params:
        return []
    cmd = ["sqlmap", "-u", f"{url}?{urlencode(params)}" if method.upper() == "GET" else url,
           "--batch", "--level", "2", "--risk", "1", "--smart", "--flush-session"]
    if method.upper() == "POST":
        cmd += ["--data", urlencode(params)]
    code, out, _ = await _run(cmd, timeout)
    findings: list[Finding] = []
    if "is vulnerable" in out or "sqlmap identified the following injection point" in out:
        findings.append(
            Finding(
                category=Category.SQLI,
                title="SQL injection confirmed by sqlmap",
                severity=Severity.CRITICAL,
                confidence="confirmed",
                url=url,
                description="sqlmap confirmed an injectable parameter.",
                evidence=out[-500:],
                remediation="Use parameterized queries; validate and least-privilege the DB account.",
                cwe="CWE-89",
                module="sqlmap",
                verified=True,
            )
        )
    return findings


def missing_tools_note() -> list[str]:
    return [name for name in ("nuclei", "nmap", "sqlmap") if not tool_available(name)]


def host_from_url(url: str) -> str:
    return urlparse(url).hostname or url
