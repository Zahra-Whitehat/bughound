"""Core data models for scans, findings and reports."""

from __future__ import annotations

import enum
import hashlib
from datetime import datetime, timezone

from pydantic import BaseModel, Field


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


class Category(str, enum.Enum):
    """Vulnerability classes tracked by the agent (maps to the bug-hunter checklist)."""

    SQLI = "SQL Injection"
    NOSQLI = "NoSQL Injection"
    CMD_INJECTION = "OS Command Injection"
    XXE = "XML External Entity (XXE)"
    LDAP_HEADER_INJECTION = "LDAP / Header Injection"

    IDOR = "IDOR"
    PRIV_ESC = "Privilege Escalation"
    PATH_TRAVERSAL = "Path Traversal / LFI / RFI"

    SSRF = "Server-Side Request Forgery (SSRF)"
    RCE = "Remote Code Execution"
    DESERIALIZATION = "Insecure Deserialization"
    RACE_CONDITION = "Race Condition / TOCTOU"

    OAUTH_SAML = "OAuth / SAML Misconfiguration"
    SESSION = "Session Fixation / Hijacking"
    BRUTE_FORCE = "Brute-Force / Credential Stuffing"
    MFA_BYPASS = "MFA Bypass"

    XSS = "Cross-Site Scripting (XSS)"
    CSRF = "Cross-Site Request Forgery (CSRF)"
    CORS = "CORS Misconfiguration"
    CLICKJACKING = "Clickjacking"

    BUSINESS_LOGIC = "Business Logic Flaw"
    INFO_DISCLOSURE = "Information Disclosure / Source Exposure"
    MISCONFIG = "Security Misconfiguration"
    CRYPTO = "Cryptographic Issue (secrets / JWT / weak hashing)"

    OPEN_REDIRECT = "Open Redirect"
    TLS = "TLS / Transport Security"


class Finding(BaseModel):
    """A single potential vulnerability, with evidence for verification."""

    category: Category
    title: str
    severity: Severity
    confidence: str = "tentative"  # tentative | firm | confirmed
    url: str
    description: str = ""
    evidence: str = ""
    request: str | None = None
    response_excerpt: str | None = None
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    cwe: str | None = None
    module: str = ""
    verified: bool = False
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def fingerprint(self) -> str:
        raw = f"{self.category.name}|{self.url}|{self.title}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


class Target(BaseModel):
    """A scan target and its authorization state."""

    url: str
    scheme: str
    host: str
    port: int
    authorized: bool = False
    authorization_note: str = ""


class ScanConfig(BaseModel):
    target_url: str
    max_urls: int = 40
    max_depth: int = 2
    timeout: float = 15.0
    concurrency: int = 8
    aggressive: bool = False  # allow active exploitation payloads
    user_agent: str = "bughound/0.1 (authorized security testing)"
    modules: list[str] | None = None  # None => all enabled
    extra_headers: dict[str, str] = Field(default_factory=dict)
    use_external_tools: bool = True


class ScanResult(BaseModel):
    target: Target
    config: ScanConfig
    findings: list[Finding] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    modules_run: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    stats: dict[str, int] = Field(default_factory=dict)

    def add(self, finding: Finding) -> None:
        seen = {f.fingerprint for f in self.findings}
        if finding.fingerprint not in seen:
            self.findings.append(finding)

    @property
    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (f.severity.rank, f.verified),
            reverse=True,
        )
