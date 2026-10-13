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

    # Pure-reconnaissance observations: subdomains, DNS records, technology
    # fingerprints, WAF presence, discovered endpoints, etc. These are surfaced
    # for situational awareness (attack-surface mapping) and are not themselves
    # vulnerabilities -- they are always emitted at INFO severity unless they
    # directly enable an exploit (e.g. exposed source map).
    RECON = "Reconnaissance / Attack-Surface Mapping"


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

    # ------------------------------------------------------------------
    # Exploitation / proof-of-impact fields (filled by the exploit engine
    # in aggressive mode, or by detection modules that already prove more
    # than a heuristic). These turn a "we saw a suspicious response"
    # finding into a demonstrated, reproducible exploit.
    # ------------------------------------------------------------------
    #: not_attempted | attempted | succeeded | failed
    exploit_status: str = "not_attempted"
    #: One-paragraph summary of what the exploit DEMONSTRATED (past tense).
    exploit_summary: str = ""
    #: Concrete artefacts the exploit extracted from the target:
    #: database version banner, table names, /etc/passwd lines, command
    #: output (uid=...), file contents, surviving XSS payload, redirect
    #: chain, etc. This is the strongest form of evidence in the report.
    extracted_data: list[str] = Field(default_factory=list)
    #: A ready-to-run curl command that reproduces the exploit.
    poc_curl: str = ""
    #: Verbatim raw HTTP request of the successful exploit (Burp-style).
    raw_request: str = ""
    #: Verbatim raw HTTP response (head + truncated body) of the exploit.
    raw_response: str = ""
    #: Numbered, human-friendly steps a triager can follow by hand.
    reproduction_steps: list[str] = Field(default_factory=list)
    #: Business/technical impact statement (why this matters).
    impact: str = ""

    # ------------------------------------------------------------------
    # Code-location evidence: WHERE in the application's code does this
    # vulnerability live? Filled by ``bughound.codemapper`` when the
    # application's source code is available (--source-dir), or with an
    # *inferred* sink pattern derived from black-box behaviour when it is
    # not. This turns "the /filter endpoint is injectable" into "the
    # category parameter is concatenated into the SQL string at line N of
    # app.py, inside filter_products()".
    # ------------------------------------------------------------------
    #: HTTP injection point in machine- and human-readable form.
    injection_point: str = ""
    #: Absolute/relative path of the vulnerable source file (when known).
    code_file: str = ""
    #: 1-indexed line range [start, end] of the vulnerable sink.
    code_lines: tuple[int, int] | None = None
    #: Verbatim vulnerable code excerpt (the sink and its surroundings).
    code_snippet: str = ""
    #: Name of the function/method containing the sink (when known).
    code_symbol: str = ""
    #: Reconstructed vulnerable code pattern for black-box targets
    #: (no source available): shows the shape of the sink the input
    #: demonstrably reaches.
    inferred_sink: str = ""

    # ------------------------------------------------------------------
    # False-positive analysis: produced by ``bughound.verification``.
    # Every finding carries the set of negative-control / consistency
    # checks that were executed against it, so the report can answer the
    # question "how do we KNOW this is not a false positive?" with
    # concrete, reproducible evidence instead of an assertion.
    # ------------------------------------------------------------------
    #: low | medium | high -- assessed risk that this finding is a FP.
    fp_risk: str = ""
    #: One-paragraph human verdict summarising the FP analysis.
    fp_verdict: str = ""
    #: Executed checks: [{name, passed, detail}].
    verification_checks: list[dict] = Field(default_factory=list)

    # ------------------------------------------------------------------
    # Attack-chain provenance (0.7, exploit-chainer): a finding produced
    # by *combining* other findings (e.g. traversal -> config read ->
    # credentials -> login) records the fingerprints it was chained from
    # plus a one-paragraph narrative of the chain. This is the
    # Bug-Bounty-Agents 'exploit-chainer' persona: one weak link alone is
    # Medium, chained it is Critical -- and the report shows the chain.
    # ------------------------------------------------------------------
    #: Fingerprints of the findings this one was chained from.
    chain_of: list[str] = Field(default_factory=list)
    #: Human-readable chain narrative ("A + B -> C because ...").
    chain_note: str = ""
    #: Short chain label used for grouping in the report (e.g.
    #: "traversal-to-credentials", "xss-to-session-theft").
    chain_label: str = ""

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
    # Default timeout bumped from 15s -> 30s: many real-world targets
    # (PortSwigger labs, serverless cold starts, slow shared hosting) take
    # >15s on the first hit and would silently fail with the old default.
    timeout: float = 30.0
    concurrency: int = 8
    aggressive: bool = False  # allow active exploitation payloads
    # Default to a recent Chrome UA: many sites block non-browser agents
    # outright (return 403 / reset connection), which made the old
    # `bughound/0.x` default produce silent "0 URLs" scans. Operators can
    # always override via --user-agent on the CLI.
    user_agent: str = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
    modules: list[str] | None = None  # None => all enabled
    extra_headers: dict[str, str] = Field(default_factory=dict)
    use_external_tools: bool = True
    # Request budget for the objective-completion (solve) phase on training
    # labs. Caps how many HTTP requests the generic strategy ladder may spend
    # so completing an objective can never turn into an unbounded or
    # throttle-aggravating request storm (0.9.0).
    solve_budget: int = 220
    # Post-detection exploitation phase: when aggressive mode is enabled,
    # detected findings are re-targeted with safe, non-destructive exploits
    # that prove real impact (extract DB banner, read /etc/passwd, run `id`,
    # confirm script-tag survival, fetch loopback content...). Disable with
    # --no-exploit on the CLI or exploit=false on the web API.
    exploit: bool = True
    # Optional path to the target application's source code. When provided,
    # the code mapper pinpoints the vulnerable sink (file + line + excerpt)
    # for every finding, so the report can show *where in the code* each
    # vulnerability happens -- not just which HTTP parameter is injectable.
    source_dir: str = ""
    # Direct-exploit mode: operator-designated URLs to work through the full
    # exploit chain regardless of what the crawler/detector found. Use when
    # you already know the vulnerable endpoint (labs: --exploit-endpoint
    # 'https://lab.net/filter' --exploit-param category).
    exploit_endpoints: list[str] = Field(default_factory=list)
    exploit_param: str = ""
    # Raw-body direct exploitation (XML/JSON endpoints behind input filters):
    # ``exploit_body`` is a body template whose ``{INJ}`` marker receives the
    # payload; ``exploit_encode`` names the WAF-bypass encoding applied at the
    # marker. Example (PortSwigger "SQL injection with filter bypass via XML
    # encoding"):
    #   --exploit-endpoint 'https://lab/product/stock' \
    #   --exploit-body '<stockCheck><productId>1</productId><storeId>{INJ}</storeId></stockCheck>' \
    #   --exploit-content-type application/xml --exploit-encode xml-entities
    exploit_method: str = ""  # default: POST when a body template is given
    exploit_content_type: str = ""
    exploit_body: str = ""
    exploit_encode: str = ""  # "" (none) | "xml-entities"

    # ------------------------------------------------------------------
    # Sn1per-style scan modes (0.7). When ``mode`` is empty the legacy
    # aggressive/exploit flags above decide behaviour unchanged; when set
    # (stealth | normal | aggressive | nuke) ``bughound.modes.apply_mode``
    # expands the mode into these same knobs so engine/report code only
    # ever reads the expanded flags.
    # ------------------------------------------------------------------
    mode: str = ""  # "" | stealth | normal | aggressive | nuke
    # Opt-in default-credential testing (Sn1per's ``-b``). Never enabled
    # implicitly: only ``--brute`` or nuke mode turns it on, and even then
    # the check caps itself at a handful of attempts per login form.
    bruteforce: bool = False
    # Workspace name (Sn1per ``-w``): reports and logs land under
    # reports/<workspace>/ so continuous monitoring runs stay organized.
    workspace: str = ""


class ScanResult(BaseModel):
    target: Target
    config: ScanConfig
    findings: list[Finding] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    modules_run: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    stats: dict[str, int] = Field(default_factory=dict)
    # Structured reconnaissance data collected by passive recon modules.
    # Populated incrementally by modules via ``ScanContext.recon``; the
    # reporting layer renders this as a dedicated "Reconnaissance" section so
    # operators get a single attack-surface overview alongside the findings.
    # Keys are stable across runs (see ``RECON_KEYS``).
    recon: dict[str, object] = Field(default_factory=dict)
    # Recon-informed attack plan produced by ``bughound.agents.planner``
    # after the recon squad finishes (0.7): focus areas, tech-specific
    # guidance and WAF notes that steer the rest of the scan and are
    # rendered as the report's "Attack plan" section.
    plan: dict[str, object] = Field(default_factory=dict)
    # Objective-completion record produced by ``bughound.solving`` (0.7.1):
    # when the target is a training lab (PortSwigger Academy & friends) this
    # tracks whether the intended exploitation objective was fully completed
    # (e.g. credentials extracted AND admin login performed) and how.
    objective: dict[str, object] = Field(default_factory=dict)

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
